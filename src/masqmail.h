/*  MasqMail
    Copyright (C) 1999 Oliver Kurth

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/
#include <config.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

#include <glib.h>

#ifdef ENABLE_IDENT
#include "libident/ident.h"
#endif

#include "lookup.h"

typedef
struct _interface
{
  gchar *address;
  gint port;
} interface;

#define ADDR_FLAG_DELIVERED 0x01
#define ADDR_FLAG_DEFERED 0x02
#define ADDR_FLAG_FAILED 0x04
#define ADDR_FLAG_NOEXPAND 0x80

typedef struct _address
{
  gchar *address;
  gchar *local_part;
  gchar *domain;
  gint flags;
  GList *children;
  struct _address *parent;
} address;

#define adr_mark_delivered(adr) { adr->flags |= ADDR_FLAG_DELIVERED; }
#define adr_unmark_delivered(adr) { adr->flags &= ~ADDR_FLAG_DELIVERED; }
#define adr_is_delivered(adr) ((adr->flags & ADDR_FLAG_DELIVERED) != 0 )

typedef
struct _connect_route
{
  gchar *name;
  gchar *filename;

  gchar *protocol;

  gboolean is_local_net;

  GList *allowed_mail_locals;
  GList *not_allowed_mail_locals;
  GList *allowed_rcpt_domains;
  GList *not_allowed_rcpt_domains;

  gchar *mail_host;
  gchar *wrapper;

  gboolean do_correct_helo;

  gchar *set_h_from_domain;
  gchar *set_h_reply_to_domain;
  gchar *set_return_path_domain;

  GList *map_h_from_addresses;
  GList *map_h_reply_to_addresses;
  GList *map_return_path_addresses;

  gboolean expand_h_sender_domain;
  gboolean expand_h_sender_address;

  GList *resolve_list;

  gchar *auth_name;
  gchar *auth_login;
  gchar *auth_secret;

  gchar *pop3_login;

  gchar *pipe;
  
  gboolean pipe_fromline;
  gboolean pipe_fromhack;
} connect_route;

typedef struct _route_file_list
{
  gchar *name;
  GList *file_list;
} route_file_list;

typedef struct _get_conf
{
  gchar *protocol;
  gchar *server_name;
  guint server_port;
  gchar *wrapper;
  gchar *login_user;
  gchar *login_pass;
  address *address;
  gboolean do_keep;
  gboolean do_uidl;
  gint max_size;

  GList *resolve_list;

} get_conf;

typedef
struct _masqmail_conf
{
  gint mail_uid;
  gint mail_gid;

  gint orig_uid;
  gint orig_gid;

  gboolean run_as_user;

  gchar *mail_dir;
  gchar *spool_dir;
  gchar *log_dir;

  gint debug_level;
  gboolean use_syslog;
  guint log_max_pri;

  gchar *host_name;
  GList *local_hosts;
  GList *local_nets;
  GList *listen_addresses;
  guint remote_port;

  GList *ident_trusted_nets;

  gboolean do_queue;

  gchar *mda;
  gboolean mda_fromline;
  gboolean mda_fromhack;

  gboolean pipe_fromline;
  gboolean pipe_fromhack;

  gchar *alias_file;
  int (*alias_local_cmp)(const char *, const char *);

  route_file_list *local_net_routes;
  GList *connect_routes; /* list of route_list */

  gchar *online_detect;
  gchar *online_file;
  interface *mserver_iface;

  GList *get_names;
} masqmail_conf;

extern masqmail_conf conf;

typedef
struct _table_pair
{
  gchar *key;
  gpointer *value;
} table_pair;


typedef
enum _prot_id
{
  PROT_LOCAL = 0,
  PROT_BSMTP,
  PROT_SMTP,
  PROT_ESMTP,
  PROT_POP3,
  PROT_APOP,
  PROT_NUM
}prot_id;

extern gchar *prot_names[];

typedef
enum _header_id
{
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
  HEAD_NUM_IDS,
  HEAD_STATUS,
  HEAD_UNKNOWN = HEAD_NUM_IDS,
  HEAD_NONE = -1,
}header_id;

typedef
struct _header_name
{
  gchar *header;
  header_id id;
}header_name;

typedef
struct _header
{
  header_id id;
  gchar *header;
  gchar *value;
}header;


typedef
struct _message
{
  gchar *uid;

  gchar *received_host;
  prot_id received_prot;
  gchar *ident;
  gint transfer_id; /* for multiple messages per transfer */

  address *return_path;
  GList *rcpt_list;
  GList *non_rcpt_list;

  GList *hdr_list;
  GList *data_list;

  gint data_size;
  time_t received_time;

  gchar *full_sender_name;
}message;

typedef
struct _msg_out
{
  message *msg;
  
  address *return_path;
  GList *rcpt_list;

  GList *hdr_list;
  GList *xtra_hdr_list;
}msg_out;

typedef
struct _msgout_perhost
{
  gchar *host;
  GList *msgout_list;
} msgout_perhost;

/* flags for accept() */
/*#define ACC_LOCAL      0x01 (we better use received_host == NULL) */
#define ACC_HEAD_FROM_RCPT 0x01 /* create To: Header from rcpt_list (cmd line) */
#define ACC_DEL_RCPTS      0x02 /* -t option, delete rcpts */
#define ACC_DEL_BCC        0x04 /* -t option, delete Bcc header */
#define ACC_RCPT_FROM_HEAD 0x08 /* -t option, get rcpts from headers */
#define ACC_NODOT_TERM     0x10 /* a dot on a line itself does not end
				   the message (-oi option) */
#define ACC_NO_RECVD_HDR   0x20 /* do not create a Received: header */
#define ACC_MAIL_FROM_HEAD 0x40 /* get return path from header */
#define ACC_NODOT_RELAX    0x80 /* do not be picky if message ist not terminated by a dot on a line */

#define DLVR_LOCAL 0x01
#define DLVR_LAN 0x02
#define DLVR_ONLINE 0x04
#define DLVR_ALL (DLVR_LOCAL|DLVR_LAN|DLVR_ONLINE)

/* transport flags */
#define MSGSTR_FROMLINE 0x01
#define MSGSTR_FROMHACK 0x02

typedef
enum _accept_error
{
  AERR_OK = 0,
  AERR_TIMEOUT,
  AERR_EOF,
  AERR_OVERFLOW,
  AERR_SYNTAX,
  AERR_NOSPOOL,
  AERR_NORCPT,
  AERR_UNKNOWN
}accept_error;

#define BUF_LEN 1024
#define MAX_ADDRESS 256
#define MAX_DATALINE 4096

typedef
enum _smtp_cmd_id
{
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
  SMTP_EOF = -1,
  SMTP_ERROR = -2,
} smtp_cmd_id;

typedef
struct _smtp_cmd
{
  smtp_cmd_id id;
  gchar *cmd;
} smtp_cmd;

typedef
struct _smtp_connection
{
  gchar *remote_host;

  prot_id prot;
  gint next_id;
  
  gboolean helo_seen;
  gboolean from_seen;
  gboolean rcpt_seen;

  message *msg;
}smtp_connection;

/* alias.c*/
GList *alias_expand(GList *alias_table, GList *rcpt_list, GList *non_rcpt_list);

/* conf.c */
gboolean read_conf(gchar *filename);
connect_route *read_route(gchar *filename, gboolean is_local_net);
GList *read_route_list(route_file_list *r_list, gboolean is_local_net);
get_conf *read_get_conf(gchar *filename);
connect_route *create_local_route();

/* message.c */
message *create_message(void);
void destroy_message(message *msg);
void destroy_msg_list(GList *msg_list);

void msg_free_data(message *msg);
gint msg_calc_size(message *msg, gboolean is_smtp);

msg_out *create_msg_out(message *msg);
msg_out *clone_msg_out(msg_out *msgout_orig);
GList *create_msg_out_list(GList *msg_list);
void destroy_msg_out(msg_out *msgout);
void destroy_msg_out_list(GList *msgout_list);

address *create_address(gchar *path, gboolean is_rfc821);
address *create_address_qualified(gchar *path, gboolean is_rfc821,
				  gchar *domain);
address *create_address_pipe(gchar *path);
void destroy_address(address *adr);
address *copy_modify_address(const address *orig, gchar *l_part, gchar *dom);
#define copy_address(adr) copy_modify_address(adr, NULL, NULL)
address *addr_find_ancestor(address *adr);
gboolean adr_is_delivered_children(address *adr);

/* accept.c */
accept_error accept_message(FILE *in, message *msg,
			    guint flags);

/* header.c */
gchar *rec_timestamp();
GList *find_header(GList *hdr_list, header_id id, gchar *hdr_str);
void header_unfold(header *hdr);
void header_fold(header *hdr);
header *create_header(header_id id, gchar *fmt, ...);
void destroy_header(header *hdr);
header *copy_header(header *hdr);
header *get_header(gchar *line);

/* smtp_in.c */
void smtp_in(FILE *in, FILE *out, gchar *remote_host, gchar *ident);

/* listen.c */
void listen_port(GList *adr_list, gint qival, char *argv[]);

/* parse.c */
gboolean split_address(const gchar *path, gchar **local_part, gchar **domain,
		       gboolean is_rfc821);
gboolean parse_address_rfc822(gchar *string,
		       gchar **local_begin, gchar **local_end,
		       gchar **domain_begin, gchar **domain_end,
			      gchar **address_end);
gboolean parse_address_rfc821(gchar *string,
			      gchar **local_begin, gchar **local_end,
			      gchar **domain_begin, gchar **domain_end,
			      gchar **address_end);
address *_create_address(gchar *string, gchar **end, gboolean is_rfc821);
address *create_address_rfc821(gchar *string, gchar **end);
address *create_address_rfc822(gchar *string, gchar **end);
GList *adr_list_append_rfc822(GList *adr_list, gchar *string, gchar *domain);
gboolean addr_isequal(address *adr1, address *adr2);

/* connect.c */
mxip_addr *connect_hostlist(int *psockfd, gchar *host, guint port,
			  GList *addr_list);
mxip_addr *connect_resolvelist(int *psockfd, gchar *host, guint port,
			     GList *res_funcs);

/* deliver.c */
void msg_rcptlist_local(GList *rcpt_list, GList **, GList **);
gboolean deliver_local(msg_out *msgout);
gboolean deliver_msglist_host(connect_route *route, GList *msg_list, gchar *host, GList *res_list);
gboolean deliver_route_msgout_list(connect_route *route, GList *msgout_list);
gboolean deliver_route_msg_list(connect_route *route, GList *msgout_list);
gboolean deliver_finish(msg_out *msgout);
gboolean deliver_finish_list(GList *msgout_list);
gboolean deliver_msg_list(GList *msg_list, guint flags);
gboolean deliver(message *msg);

/* get.c */
gboolean get_from_file(gchar *fname);
gboolean get_from_name(gchar *name);
gboolean get_all(void);
gboolean pop_before_smtp(gchar *fname);

/* local.c */
gboolean append_file(message *msg, GList *hdr_list, gchar *user);
gboolean pipe_out(message *msg, GList *hdr_list, address *rcpt, gchar *cmd, guint flags);

/* log.c */
gboolean logopen(void);
void logclose(void);
void vlogwrite(int pri, const char *fmt, va_list args);
void logwrite(int pri, const char *fmt, ...);
void debugf(const char *fmt, ...);
void vdebugf(const char *fmt, va_list args);
void maillog(const char *fmt, ...);

/* mserver.c */
gchar *mserver_detect_online();

/* spool.c */
gboolean spool_read_data(message *msg);
gboolean spool_read_data(message *msg);
message *msg_spool_read(gchar *uid, gboolean do_readdata);
gboolean spool_write(message *msg, gboolean do_writedata);
gboolean spool_lock(gchar *uid);
gboolean spool_unlock(gchar *uid);
gboolean spool_delete_all(message *msg);

/* queue.c */
GList *read_queue(gboolean do_readdata);
gboolean queue_run(void);
gboolean queue_run_online(void);
void queue_list(void);
gboolean queue_delete(gchar *uid);

/* online.c */
gchar *detect_online();
void set_online_name(gchar *name);

/* permissions.c */
gboolean is_ingroup(uid_t uid, gid_t gid);
void set_euidgid(gint uid, gint gid, gint *old_uid, gint *old_gid);
void set_identity(uid_t old_uid, gchar *task_name);

/* rewrite.c */
gboolean set_address_header_domain(header *hdr, gchar *domain);
gboolean map_address_header(header *hdr, GList *table);

/* route.c */
route_file_list *find_route_file_list(GList *list, gchar *name);
msgout_perhost *create_msgout_perhost(gchar *host);
void destroy_msgout_perhost(msgout_perhost *mo_ph);
void rewrite_headers(msg_out *msgout, connect_route *route);
void rcptlist_with_one_of_hostlist(GList *rcpt_list, GList *host_list,
				     GList **, GList **);
gboolean route_strip_msgout(connect_route *route, msg_out *msgout);
msg_out *route_prepare_msgout(connect_route *route, msg_out *msgout);
GList *route_msgout_list(connect_route *route, GList *msgout_list);
gboolean route_is_allowed_mail_local(connect_route *route, address *ret_path);
void msg_rcptlist_route(connect_route *route, GList *rcpt_list,
			GList **p_rcpt_list, GList **p_non_rcpt_list);

/* tables.c */
table_pair *create_pair_string(gchar *key, gpointer value);
table_pair *parse_table_pair(gchar *line, char delim);
gpointer *table_find_func(GList *table_list, gchar *key, int (*cmp_func)(const char *, const char *));
gpointer *table_find(GList *table_list, gchar *key);
gpointer *table_find_case(GList *table_list, gchar *key);
gpointer *table_find_fnmatch(GList *table_list, gchar *key);
GList *table_read(gchar *fname, gchar delim);
void destroy_table(GList *table);

/* other things */

#define foreach(list, node)\
for((node) = g_list_first(list);\
    (node);\
    (node) = g_list_next(node))

#define DEBUG(level) if(level <= conf.debug_level)

#ifndef HAVE_GETLINE
#define getline(buf, size, file) getdelim(buf, size, '\n', file)
#endif

#ifndef HAVE_FDATASYNC
#define fdatasync(fd) fsync(fd)
#endif

#ifndef CONF_FILE
#define CONF_FILE "/etc/masqmail.conf"
#endif

#ifndef va_copy
#ifdef __va_copy
#define va_copy(ap1, ap2) __va_copy(ap1, ap2)
#else
#define va_copy(ap1, ap2) G_VA_COPY(ap1, ap2)
#endif
#endif

