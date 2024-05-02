// SPDX-FileCopyrightText: (C) Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  smtp_out.h
*/

#include "masqmail.h"

#define SMTP_BUF_LEN 1024
#define SMTP_SIZE_ADD 1024  /* add to the size of a message */

#define SMTP_INITIAL_TIMEOUT 5*60
#define SMTP_CMD_TIMEOUT 5*60
#define SMTP_DATA_TIMEOUT 5*60
#define SMTP_FINAL_TIMEOUT 10*60

typedef enum _smtp_error {
	smtp_ok = 0,  /* mail was delivered to at least one recpient */
	smtp_trylater,  /* server responded with 4xx */
	smtp_fail,  /* server responded with 5xx */
	smtp_timeout,  /* connection timed out */
	smtp_eof,  /* got unexpected EOF */
	smtp_syntax,  /* unexpected response */
	smtp_cancel  /* we gave up (eg. size) */
} smtp_error;


typedef struct _smtp_base {
	FILE *in;
	FILE *out;

	gchar *remote_host;
	gchar *helo_name;

	gchar *buffer;
	gint last_code;

	gboolean is_wrapped;

	gboolean use_size;
	gboolean use_pipelining;
	gboolean use_auth;

	gssize max_size;

	gchar **auth_names;

	gchar *auth_name;
	gchar *auth_login;
	gchar *auth_secret;

	smtp_error error;

} smtp_base;

gchar *set_heloname(smtp_base *psb, const gchar *default_name, gboolean do_correct);
gboolean set_auth(smtp_base *psb, const gchar *name, const gchar *login, const gchar *secret);
void destroy_smtpbase(smtp_base *psb);
smtp_base *smtp_out_open(const gchar *host, gint port, const GList *resolve_list, gchar **err_msg);
smtp_base *smtp_out_open_child(const gchar *host, const gchar *cmd, gchar **err_msg);
gboolean smtp_out_rset(smtp_base *psb);
gboolean smtp_out_init(smtp_base *psb, gboolean instant_helo, gchar **err_msg);
void smtp_out_msg(smtp_base *psb, message *msg, const address *return_path,
                  GList *rcpt_list, const GList *hdr_list, gchar **err_msg);
void smtp_out_quit(smtp_base *psb);
void smtp_out_mark_rcpts(smtp_base *psb, GList *rcpt_list);
