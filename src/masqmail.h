// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "lookup.h"

#include <glib.h>

#include <ctype.h>
#include <stdio.h>
#include <netinet/in.h>
#include <syslog.h>  // for log levels

#include <config.h>

typedef struct _interface {
	gchar *address;
	gint port;
} interface;

#define ADDR_FLAG_DELIVERED 0x01
#define ADDR_FLAG_DEFERED 0x02
#define ADDR_FLAG_FAILED 0x04
#define ADDR_FLAG_LAST_ROUTE 0x40

typedef struct _address {
	gchar *address;  /* full addr string: `markus <meillo@marmaro.de>' */
	gchar *local_part;  /* in this example: `meillo' */
	gchar *domain;  /* in this example: `marmaro.de' */
	gint flags;
	GList *children;
	struct _address *parent;
} address;

#define addr_mark_delivered(addr) { addr->flags |= ADDR_FLAG_DELIVERED; }
#define addr_unmark_delivered(addr) { addr->flags &= ~ADDR_FLAG_DELIVERED; }
#define addr_is_delivered(addr) ((addr->flags & ADDR_FLAG_DELIVERED) != 0 )

#define addr_mark_defered(addr) { addr->flags |= ADDR_FLAG_DEFERED; }
#define addr_unmark_defered(addr) { addr->flags &= ~ADDR_FLAG_DEFERED; }
#define addr_is_defered(addr) ((addr->flags & ADDR_FLAG_DEFERED) != 0 )

#define addr_mark_failed(addr) { addr->flags |= ADDR_FLAG_FAILED; }
#define addr_unmark_failed(addr) { addr->flags &= ~ADDR_FLAG_FAILED; }
#define addr_is_failed(addr) ((addr->flags & ADDR_FLAG_FAILED) != 0 )

typedef struct _connect_route {
	gchar *name;
	gchar *filename;

	gboolean last_route;

	GList *allowed_senders;
	GList *denied_senders;
	GList *allowed_recipients;
	GList *denied_recipients;
	GList *allowed_from_hdrs;
	GList *denied_from_hdrs;

	interface *mail_host;
	gboolean connect_error_fail;
	GList *resolve_list;
	gchar *helo_name;
	gboolean do_correct_helo;
	gboolean instant_helo;
	gboolean do_pipelining;
	gchar *auth_name;
	gchar *auth_login;
	gchar *auth_secret;
	gchar *wrapper;

	GList *map_h_from_addresses;
	GList *map_h_reply_to_addresses;
	GList *map_h_mail_followup_to_addresses;
	GList *map_return_path_addresses;

	gchar *pipe;
	gboolean pipe_fromline;
	gboolean pipe_fromhack;
} connect_route;

typedef struct _masqmail_conf {
	gint mail_uid;
	gint mail_gid;

	gint orig_uid;
	gint orig_gid;

	gboolean run_as_user;

	gchar *mail_dir;
	gchar *lock_dir;
	gchar *spool_dir;
	gchar *log_dir;

	gint debug_level;
	gboolean use_syslog;

	gchar *host_name;
	GList *local_hosts;
	GList *local_addresses;
	GList *not_local_addresses;
	GList *listen_addresses;

	/*
	**  ANSI C defines signed long to be at least 32bit
	**  i.e. ca. 2 GiB max; that should be enough.
	*/
	gssize max_msg_size;

	gboolean do_save_envelope_to;

	gboolean defer_all;
	gboolean do_relay;

	gboolean do_queue;

	gchar *mbox_default;
	GList *mbox_users;
	GList *mda_users;

	gchar *mda;
	gboolean mda_fromline;
	gboolean mda_fromhack;

	gboolean pipe_fromline;
	gboolean pipe_fromhack;

	gchar *alias_file;
	int (*localpartcmp) (const char *, const char *);
	gchar *globalias_file;

	GList *perma_routes;
	GList *query_routes;  /* list of pairs which point to lists */

	gchar *online_query;

	gchar *errmsg_file;
	gchar *warnmsg_file;
	GList *warn_intervals;
	gint max_defer_time;

	gchar *log_user;
} masqmail_conf;

extern masqmail_conf conf;

typedef struct _table_pair {
	gchar *key;
	gpointer value;
} table_pair;


/* must match the contents of prot_names[] in accept.c */
typedef enum _prot_id {
	PROT_LOCAL = 0,
	PROT_SMTP,
	PROT_ESMTP,
	PROT_NUM
} prot_id;

extern gchar *prot_names[];

/* keep in sync with header_names array! */
typedef enum _header_id {
	HEAD_FROM = 0,
	HEAD_SENDER,
	HEAD_TO,
	HEAD_CC,
	HEAD_BCC,
	HEAD_DATE,
	HEAD_MESSAGE_ID,
	HEAD_REPLY_TO,
	HEAD_SUBJECT,
	HEAD_RETURN_PATH,
	HEAD_ENVELOPE_TO,
	HEAD_RECEIVED,
	HEAD_UNKNOWN
} header_id;

typedef struct _header {
	header_id id;
	gchar *header;
	gchar *value;
} header;


typedef struct _message {
	gchar *uid;

	gchar *received_host;
	prot_id received_prot;
	gchar *ident;
	gint transfer_id;  /* for multiple messages per transfer */

	address *return_path;
	GList *rcpt_list;
	GList *non_rcpt_list;

	GList *hdr_list;
	GList *data_list;

	gssize data_size;
	time_t received_time;
	time_t warned_time;

	gchar *full_sender_name;
} message;

typedef struct _msg_out {
	message *msg;

	address *return_path;
	GList *rcpt_list;

	GList *hdr_list;
	GList *xtra_hdr_list;  /* rewritten headers */
} msg_out;

typedef struct _msgout_perhost {
	gchar *host;
	GList *msgout_list;
} msgout_perhost;

/* flags for accept() */
#define ACC_RCPT_FROM_HEAD 0x08  /* -t option, get rcpts from headers */
#define ACC_DOT_IGNORE     0x10  /* a dot on a line itself does not end the message (-oi option) */
#define ACC_NODOT_RELAX    0x80  /* do not be picky if message ist not terminated by a dot on a line */
#define ACC_SAVE_ENVELOPE_TO 0x0100  /* save an existent Envelope-to header as X-Orig-Envelope-to */

#define DLVR_LOCAL 0x01
#define DLVR_ONLINE 0x02
#define DLVR_ALL (DLVR_LOCAL|DLVR_ONLINE)

/* transport flags */
#define MSGSTR_FROMLINE 0x01
#define MSGSTR_FROMHACK 0x02

typedef enum _accept_error {
	AERR_OK = 0,
	AERR_TIMEOUT,
	AERR_EOF,
	AERR_NORCPT,
	AERR_SIZE,  /* max msg size exeeded (SMTP SIZE) */
	AERR_UNKNOWN
} accept_error;

#define BUF_LEN 1024
#define MAX_ADDRESS 256
#define MAX_DATALINE 4096

// keep in sync with smtp_cmds!
typedef enum _smtp_cmd_id {
	SMTP_HELO = 0,
	SMTP_EHLO,
	SMTP_MAIL_FROM,
	SMTP_RCPT_TO,
	SMTP_DATA,
	SMTP_QUIT,
	SMTP_RSET,
	SMTP_NOOP,
	SMTP_HELP,
	SMTP_NUM_IDS,
	SMTP_ERROR = -1,
} smtp_cmd_id;

typedef struct _smtp_connection {
	prot_id prot;
	gint next_id;

	gboolean helo_seen;
	gboolean from_seen;
	gboolean rcpt_seen;
} smtp_connection;

/* alias.c*/
gboolean addr_is_local(address *addr);
GList *alias_expand(GList *alias_table, GList *rcpt_list, GList *non_rcpt_list,
		int doglob);

/* child.c */
int child(const char *command);

/* conf.c */
void init_conf(void);
gboolean read_conf(gchar *filename);
GList *read_route_list(GList *rf_list);
void destroy_route(connect_route *r);
void destroy_route_list(GList *list);

/* expand.c */
GList *var_table_rcpt(GList *var_table, address *rcpt);
GList *var_table_msg(GList *var_table, message *msg);
GList *var_table_conf(GList *var_table);
gint expand(GList *var_list, gchar *format, gchar *result, gint result_len);

/* message.c */
message *create_message(void);
void destroy_message(message *msg);
void destroy_msg_list(GList *msg_list);
void msg_free_data(message *msg);
gssize msg_calc_size(message *msg, gboolean is_smtp);

msg_out *create_msg_out(message *msg);
msg_out *clone_msg_out(msg_out *msgout_orig);
void destroy_msg_out(msg_out *msgout);
void destroy_msg_out_list(GList *msgout_list);

/* address.c */
address *create_address(gchar *path, gboolean is_rfc821);
address *create_address_qualified(gchar *path, gboolean is_rfc821, gchar *domain);
address *create_address_pipe(gchar *path);
void destroy_address(address *addr);
address *copy_modify_address(const address *orig, gchar *l_part, gchar *dom);
#define copy_address(addr) copy_modify_address(addr, NULL, NULL)
gboolean addr_isequal(address *addr1, address *addr2, int (*cmpfunc) (const char*, const char*));
gboolean addr_isequal_parent(address *addr1, address *addr2, int (*cmpfunc) (const char*, const char*));
address *addr_find_ancestor(address *addr);
gboolean addr_is_delivered_children(address *addr);
gboolean addr_is_finished_children(address *addr);
gchar *addr_string(address *addr);

/* accept.c */
accept_error accept_message(FILE *in, message *msg, guint flags);

/* header.c */
gchar *rec_timestamp(void);
header *find_header(GList *hdr_list, header_id id);
header *create_header(header_id id, gchar *fmt, ...) G_GNUC_PRINTF(2, 3);
void destroy_header(header *hdr);
header *copy_header(header *hdr);
header *get_header(gchar *line);

/* smtp_in.c */
void smtp_in(FILE *in, FILE *out, gchar *remote_host);

/* listen.c */
void listen_port(GList *addr_list, gint qival);

/* parse.c */
gboolean parse_address_rfc822(gchar *string, gchar **local_begin, gchar **local_end, gchar **domain_begin, gchar **domain_end, gchar **address_end);
gboolean parse_address_rfc821(gchar *string, gchar **local_begin, gchar **local_end, gchar **domain_begin, gchar **domain_end, gchar **address_end);
address *_create_address(gchar *string, gchar **end, gboolean is_rfc821);
GList *addr_list_append_rfc822(GList *addr_list, gchar *string, gchar *domain);

/* connect.c */
mxip_addr *connect_resolvelist(int *psockfd, gchar *host, gint port, GList *res_funcs);

/* deliver.c */
gboolean deliver_msg_list(GList *msg_list, guint flags);
gboolean deliver(message *msg);

/* fail_msg.c */
gboolean fail_msg(message *msg, gchar *template, GList *failed_rcpts, gchar *err_fmt, va_list args);
gboolean warn_msg(message *msg, gchar *template, GList *failed_rcpts, gchar *err_fmt, va_list args);

/* interface.c */
int make_server_socket(interface *iface);

/* local.c */
gboolean append_file(message *msg, GList *hdr_list, gchar *user);
gboolean pipe_out(message *msg, GList *hdr_list, address *rcpt, gchar *cmd, guint flags);

/* log.c */
gchar *ext_strerror(int err);
void ensure_stdio(void);
void null_stdio(void);
void logopen(void);
void logclose(void);
void logwrite(int pri, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
void logerrno(int pri, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
void debugf(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
void vdebugf(const char *fmt, va_list args) G_GNUC_PRINTF(1, 0);

/* spool.c */
gboolean spool_read_data(message *msg);
message *msg_spool_read(gchar *uid);
gboolean spool_write(message *msg, gboolean do_writedata);
gboolean spool_lock(gchar *uid);
gboolean spool_unlock(gchar *uid);
gboolean spool_delete_all(message *msg);

/* queue.c */
gboolean queue_run(void);
gboolean queue_run_online(void);
void queue_list(void);
gboolean queue_delete(gchar *uid);

/* online.c */
gchar *online_query(void);

/* permissions.c */
gboolean is_privileged_user(void);
void verify_privileged_user(gchar *task_name);
void acquire_root(void);
void drop_root(void);

/* rewrite.c */
gboolean map_address_header(header *hdr, GList *table);

/* route.c */
void destroy_msgout_perhost(msgout_perhost *mo_ph);
GList *local_rcpts(GList *rcpt_list);
GList *remote_rcpts(GList *rcpt_list);
msg_out *route_prepare_msgout(connect_route *route, msg_out *msgout);
GList *route_msgout_list(GList *msgout_list);
gboolean route_sender_is_allowed(connect_route *route, address *ret_path);
gboolean route_from_hdr_is_allowed(connect_route *route, char *from_hdr);
void route_split_rcpts(connect_route *route, GList *rcpt_list, GList **p_rcpt_list, GList **p_non_rcpt_list);

/* tables.c */
table_pair *create_pair(gchar *key, gpointer value);
table_pair *create_pair_string(gchar *key, gpointer value);
table_pair *parse_table_pair(gchar *line, char delim);
gpointer table_find_func(GList *table_list, gchar *key, int (*cmp_func) (const char *, const char *));
gpointer table_find(GList *table_list, gchar *key);
gpointer table_find_case(GList *table_list, gchar *key);
gpointer table_find_fnmatch(GList *table_list, gchar *key);
GList *table_read(gchar *fname, gchar delim);
void destroy_table(GList *table);

/* timeival.c */
gint time_interval(gchar *str);

/* other things */

#define foreach(list, node)\
for((node) = g_list_first(list);\
    (node);\
    (node) = g_list_next(node))

#ifdef ENABLE_DEBUG
#define DEBUG(level) if(level <= conf.debug_level)
#else
/* hopefully the compiler optmizes this away... */
#define DEBUG(level) if(0)
#endif

#ifndef HAVE_GETLINE
#define getline(buf, size, file) getdelim(buf, size, '\n', file)
#endif

#ifndef HAVE_FDATASYNC
#define fdatasync(fd) fsync(fd)
#endif

#ifndef CONF_DIR
#define CONF_DIR "/etc/masqmail"
#endif

#define CONF_FILE CONF_DIR"/masqmail.conf"

#ifndef PID_DIR
#define PID_DIR "/var/run"
#endif

#ifndef va_copy
#ifdef __va_copy
#define va_copy(ap1, ap2) __va_copy(ap1, ap2)
#else
#define va_copy(ap1, ap2) G_VA_COPY(ap1, ap2)
#endif
#endif

/* *BSD needs this: */
extern char **environ;
