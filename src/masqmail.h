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
#include <stdint.h>
#include <netinet/in.h>
#include <syslog.h>  // for log levels

#include <config.h>
#ifdef TEST_BUILD
#  undef ENABLE_DEBUG
#endif

typedef struct _interface {
	gchar *address;
	gint port;
} interface;

typedef struct {
	gchar *address;     // full addr-spec: meillo@marmaro.de
	gchar *local_part;  // in this example: meillo
	gchar *domain;      // in this example: marmaro.de
} address;

#define ADDR_FLAG_DELIVERED 0x01
#define ADDR_FLAG_DEFERED 0x02
#define ADDR_FLAG_FAILED 0x04
#define ADDR_FLAG_ALIAS 0x10
#define ADDR_FLAG_LAST_ROUTE 0x40

typedef struct _recipient {
	address address[1];  // must be first member
	struct _recipient *parent;
	GList *children;
	gint flags;
	gint ref_count;
} recipient;

#define addr_mark_delivered(addr) { addr->flags |= ADDR_FLAG_DELIVERED; }
#define addr_unmark_delivered(addr) { addr->flags &= ~ADDR_FLAG_DELIVERED; }
#define addr_is_delivered(addr) ((addr->flags & ADDR_FLAG_DELIVERED) != 0 )

#define addr_mark_defered(addr) { addr->flags |= ADDR_FLAG_DEFERED; }
#define addr_unmark_defered(addr) { addr->flags &= ~ADDR_FLAG_DEFERED; }
#define addr_is_defered(addr) ((addr->flags & ADDR_FLAG_DEFERED) != 0 )

#define addr_mark_failed(addr) { addr->flags |= ADDR_FLAG_FAILED; }
#define addr_unmark_failed(addr) { addr->flags &= ~ADDR_FLAG_FAILED; }
#define addr_is_failed(addr) ((addr->flags & ADDR_FLAG_FAILED) != 0 )

#define addr_is_finished(addr) ((addr->flags & (ADDR_FLAG_DELIVERED | ADDR_FLAG_FAILED)) != 0)

#define addr_mark_alias(addr) { addr->flags |= ADDR_FLAG_ALIAS; }
#define addr_unmark_alias(addr) { addr->flags &= ~ADDR_FLAG_ALIAS; }
#define addr_is_alias(addr) ((addr->flags & ADDR_FLAG_ALIAS) != 0 )

typedef struct {
	address address[1];  // parsed address; must be first member
	gchar *full_address;  // full address: `markus schnalke <meillo@marmaro.de>'
} replacement;

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
	gint smtp_port;
	gboolean do_correct_helo;
	gboolean instant_helo;
	gboolean do_pipelining;
	gchar *auth_name;
	gchar *auth_login;
	gchar *auth_secret;
	gchar *wrapper;

	GList *map_h_from_addresses;
	GList *map_h_sender_addresses;
	GList *map_h_reply_to_addresses;
	GList *map_h_mail_followup_to_addresses;
	GList *map_return_path_addresses;
	GList *map_outgoing_addresses;

	gchar *pipe;
	gboolean pipe_fromline;
	gboolean pipe_fromhack;
} connect_route;

typedef struct _masqmail_conf {
	uid_t mail_uid;
	gid_t mail_gid;

	uid_t orig_uid;
	gid_t orig_gid;

	gboolean run_as_user;

	const gchar *exe_file;
	const gchar *conf_file;

	gchar *mail_dir;
	gchar *lock_dir;
	gchar *spool_dir;
	gchar *log_dir;
	gchar *pid_dir;

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
	gboolean do_background;

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

	recipient *log_user;
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
	HEAD_MAIL_FOLLOWUP_TO,
	HEAD_SUBJECT,
	HEAD_RETURN_PATH,
	HEAD_ENVELOPE_TO,
	HEAD_RECEIVED,
	HEAD_UNKNOWN
} header_id;

typedef struct _header {
	int ref_count;
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
gboolean alias_expand(GList *globalias_table, GList *alias_table, GList *rcpt_list);

/* conf.c */
void init_conf(void);
gboolean read_conf(void);
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

void destroy_ptr_list(GList *list);

/* address.c */
typedef enum { A_RFC821, A_RFC822 } addr_type_t;
address *create_address(const gchar *path, addr_type_t addr_type, const gchar *domain);
address *create_address_raw(const gchar *local_part, const gchar *domain);
void destroy_address(address *addr);
#define copy_address(addr) create_address_raw(addr->local_part, addr->domain)
gboolean addr_isequal(address *addr1, address *addr2, int (*cmpfunc) (const char*, const char*));
gboolean addr_is_local(address *addr);
gboolean domain_is_local(const gchar *domain);

recipient *create_recipient(const gchar *path, const gchar *domain);
recipient *create_recipient_raw(const gchar *local_part, const gchar *domain);
recipient *create_recipient_pipe(const gchar *path);
void destroy_recipient(recipient *addr);
GList *copy_recipient_list(GList *rcpt_list);
void destroy_recipient_list(GList *rcpt_list);
GList *addr_list_append_rfc822(GList *addr_list, const gchar *string, const gchar *domain);
gboolean addr_isequal_parent(recipient *addr1, address *addr2, int (*cmpfunc) (const char*, const char*));
recipient *addr_find_ancestor(recipient *addr);
gboolean addr_is_delivered_children(recipient *addr);
gboolean addr_is_finished_children(recipient *addr);

replacement *create_replacement(gchar *path, addr_type_t addr_type);
void destroy_replacement(replacement *addr);

/* accept.c */
accept_error accept_message(FILE *in, message *msg, guint flags);

/* header.c */
gchar *rec_timestamp(void);
header *find_header(GList *hdr_list, header_id id);
header *create_header(header_id id, gchar *fmt, ...) G_GNUC_PRINTF(2, 3);
header *create_header_raw(header_id id, gchar *txt, int offset);
void destroy_header(header *hdr);
void destroy_header_list(GList *hdr_list);
GList *copy_header_list(GList *hdr_list);
header *get_header(gchar *line);

/* smtp_in.c */
void smtp_in(FILE *in, FILE *out, gchar *remote_host);

/* listen.c */
void listen_port(GList *addr_list, gint qival);

/* parse.c */
extern const char *parse_error;
gboolean parse_address_rfc822(const gchar *string,
                              const gchar **local_begin, const gchar **local_end,
                              const gchar **domain_begin, const gchar **domain_end,
                              const gchar **address_end);
gboolean parse_address_rfc821(const gchar *string,
                              const gchar **local_begin, const gchar **local_end,
                              const gchar **domain_begin, const gchar **domain_end,
                              const gchar **address_end);

/* connect.c */
mxip_addr *connect_resolvelist(int *psockfd, gchar *host, gint port,
                               GList *res_funcs, gchar **err_msg);

/* deliver.c */
void deliver_msg_list(GList *msg_list, guint flags);
void deliver(message *msg);

/* fail_msg.c */
gboolean fail_msg(message *msg, gchar *template, GList *failed_rcpts, gchar *err_msg);
gboolean warn_msg(message *msg, gchar *template, GList *failed_rcpts, gchar *err_msg);

/* interface.c */
int make_server_socket(interface *iface);

/* local.c */
gboolean append_file(message *msg, GList *hdr_list, gchar *user);
gboolean prepare_pipe(const gchar *cmd, const gchar *what, GList *var_table,
                      gchar ***argv, gchar **out_cmd);
gboolean pipe_out(message *msg, GList *hdr_list, recipient *rcpt,
                  gchar **argv, gchar *cmd, guint flags);

/* log.c */
gchar *sysexit_str(int err);
void ensure_stdio(void);
void null_stdio(void);
void logopen(void);
void logclose(void);
void logwrite(int pri, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
void logerrno(int pri, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
void loggerror(int pri, GError *gerr, const char *fmt, ...) G_GNUC_PRINTF(3, 4);
void debugf(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
void vdebugf(const char *fmt, va_list args) G_GNUC_PRINTF(1, 0);

/* spool.c */
gboolean spool_read_data(message *msg);
message *msg_spool_read(gchar *uid);
gboolean spool_write(message *msg, gboolean do_writedata);
gboolean spool_lock(gchar *uid);
void spool_unlock(gchar *uid);
void spool_delete_all(message *msg);

/* queue.c */
void queue_run(void);
void queue_run_online(void);
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
void rewrite_headers(msg_out *msgout, const connect_route *route);
void rewrite_return_path(msg_out *msgout, const connect_route *route);

/* route.c */
void destroy_msgout_perhost(msgout_perhost *mo_ph);
void split_rcpts(GList *rcpt_list, GList *non_rcpt_list,
                 GList **local_rcpts, GList **remote_rcpts);
void route_filter_rcpts(connect_route *route, GList **rcpt_list);
msg_out *route_prepare_msgout(connect_route *route, msg_out *msgout);
GList *route_msgout_list(GList *msgout_list);
gboolean route_sender_is_allowed(connect_route *route, address *ret_path);
gboolean route_from_hdr_is_allowed(connect_route *route, address *addr);

/* tables.c */
table_pair *create_pair_base(gchar *key, gpointer value);
table_pair *create_pair(gchar *key, gchar *value);
table_pair *parse_table_pair(gchar *line, char delim);
gpointer table_find_func(GList *table_list, gchar *key, int (*cmp_func) (const char *, const char *));
gpointer table_find(GList *table_list, gchar *key);
gpointer table_find_casefold(GList *table_list, gchar *key);
gpointer table_find_fnmatch(GList *table_list, gchar *key);
gpointer table_find_fnmatch_casefold(GList *table_list, gchar *key);
GList *table_read(gchar *fname, gchar delim);
void destroy_pair_base(table_pair *p);
void destroy_pair(table_pair *p);
void destroy_table(GList *table);

/* timeival.c */
gint time_interval(gchar *str);

/* other things */

// the control variable makes 'break' work. idea stolen from Qt.
#define foreach_4_(var, ctl, node, list) \
	for (const GList *node = list, *ctl = (GList *)1; \
	     ctl && node; \
	     node = node->next, ctl = (GList *) ((uintptr_t) ctl ^ 1)) \
		for (var = node->data; ctl; ctl = 0)

#define foreach_3_(var, node, list) \
	foreach_4_ (var, node##_ctl, node, list)

#define foreach_2_(var, list) \
	foreach_4_ (var, G_PASTE(node_ctl_, __LINE__), G_PASTE(node_, __LINE__), list)

// macro overloading taken from https://stackoverflow.com/a/11763277/3685191
#define foreach_sel_(_1, _2, _3, x, ...) x
#define foreach(...) \
	foreach_sel_(__VA_ARGS__, foreach_3_, foreach_2_, NO_foreach_1)(__VA_ARGS__)

#define foreach_mut_5_(var, ctl, node, node_next, list) \
	for (GList *node, *node_next = list, *ctl = (GList *)1; \
	     ctl && (node = node_next) && (node_next = node->next, 1); \
	     ctl = (GList *) ((uintptr_t) ctl ^ 1)) \
		for (var = node->data; ctl; ctl = 0)

#define foreach_mut(var, node, list) \
	foreach_mut_5_ (var, node##_ctl, node, node##_next, list)

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

#define DO_PRAGMA(str) _Pragma(#str)
#if defined(__clang__)
#  define WARNING_PUSH DO_PRAGMA(clang diagnostic push)
#  define WARNING_POP DO_PRAGMA(clang diagnostic pop)
#  define WARNING_DISABLE(which) DO_PRAGMA(clang diagnostic ignored which)
#elif defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 406)
#  define WARNING_PUSH DO_PRAGMA(GCC diagnostic push)
#  define WARNING_POP DO_PRAGMA(GCC diagnostic pop)
#  define WARNING_DISABLE(which) DO_PRAGMA(GCC diagnostic ignored which)
#else
#  define WARNING_PUSH
#  define WARNING_POP
#  define WARNING_DISABLE(which)
#endif

/* *BSD needs this: */
extern char **environ;
