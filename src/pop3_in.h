/* pop3_in.h, Copyright 2000 (C) Oliver Kurth,
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

#ifdef ENABLE_POP3

#define POP3_BUF_LEN 1024

#define POP3_INITIAL_TIMEOUT 5*60
#define POP3_CMD_TIMEOUT 5*60
#define POP3_DATA_TIMEOUT 5*60
#define POP3_FINAL_TIMEOUT 10*60

#define POP3_FLAG_DELETE 0x01
#define POP3_FLAG_UIDL 0x02
#define POP3_FLAG_UIDL_DELE 0x04
#define POP3_FLAG_APOP 0x08

#define POP3_MAX_CHILDREN 2

typedef enum _pop3_error {
	pop3_ok = 0,
	pop3_fail,
	pop3_eof,
	pop3_timeout,
	pop3_login_failure,
	pop3_syntax
} pop3_error;

typedef struct pop3_base {
	FILE *in;
	FILE *out;
	gint sock;
	gint dup_sock;

	gchar *remote_host;
	gchar *buffer;

	gint next_id;
	gint msg_cnt;
	gint uidl_known_cnt;
	gint mbox_size;

	GList *list_uid_old;
	GList *drop_list;

	gchar *timestamp;

	guint flags;

	pop3_error error;
} pop3_base;

typedef struct _msg_info {
	gint number;
	gint size;
	gchar *uid;
	gboolean is_fetched;
	gboolean is_in_uidl;
} msg_info;

pop3_base *pop3_in_open(gchar * host, gint port, GList * resolve_list, guint flags);
pop3_base *pop3_in_open_child(gchar * cmd, guint flags);
void pop3_in_close(pop3_base * popb);
gboolean pop3_get(pop3_base * popb, gchar * user, gchar * pass, address * rcpt, address * return_path, gint max_count, gint max_size, gboolean max_size_delete);
gboolean pop3_login(gchar * host, gint port, GList * resolve_list, gchar * user, gchar * pass, guint flags);



#endif
