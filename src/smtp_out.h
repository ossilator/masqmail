/* smtp_out.h, Copyright (C) Oliver Kurth,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

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

	gint sock;
	gint dup_sock;

	gchar *remote_host;
	gchar *helo_name;

	gchar *buffer;
	gint last_code;

	gboolean use_size;
	gboolean use_pipelining;
	gboolean use_auth;

	gint max_size;

	gchar **auth_names;

	gchar *auth_name;
	gchar *auth_login;
	gchar *auth_secret;

	smtp_error error;

} smtp_base;

gchar *set_heloname(smtp_base * psb, gchar * default_name, gboolean do_correct);
gboolean set_auth(smtp_base * psb, gchar * name, gchar * login, gchar * secret);
void destroy_smtpbase(smtp_base * psb);
smtp_base *smtp_out_open(gchar * host, gint port, GList * resolve_list);
smtp_base *smtp_out_open_child(gchar * cmd, char* host);
gboolean smtp_out_rset(smtp_base * psb);
gboolean smtp_out_init(smtp_base * psb, gboolean instant_helo);
gint smtp_out_msg(smtp_base * psb, message * msg, address * return_path, GList * rcpt_list, GList * hdr_list);
gboolean smtp_out_quit(smtp_base * psb);

gint smtp_deliver(gchar * host, gint port, GList * resolve_list, message * msg, address * return_path, GList * rcpt_list);
