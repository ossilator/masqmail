/* smtp_out.c
    Copyright (C) 1999-2001 Oliver Kurth
    Copyright (C) 2010 markus schnalke <meillo@marmaro.de>

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

/*
  I always forget these rfc numbers:
  RFC 821  (SMTP)
  RFC 1869 (ESMTP)
  RFC 1870 (ESMTP SIZE)
  RFC 2197 (ESMTP PIPELINE)
  RFC 2554 (ESMTP AUTH)
*/

#include "masqmail.h"
#include "smtp_out.h"
#include "readsock.h"

#ifdef ENABLE_AUTH
#include "md5/md5.h"
#include "md5/hmac_md5.h"
#include "base64/base64.h"
#endif

void
destroy_smtpbase(smtp_base * psb)
{
	fclose(psb->in);
	fclose(psb->out);

	close(psb->sock);

	if (psb->helo_name)
		g_free(psb->helo_name);
	if (psb->buffer)
		g_free(psb->buffer);
	if (psb->auth_names)
		g_strfreev(psb->auth_names);

	if (psb->auth_name)
		g_free(psb->auth_name);
	if (psb->auth_login)
		g_free(psb->auth_login);
	if (psb->auth_secret)
		g_free(psb->auth_secret);
}

gchar*
set_heloname(smtp_base * psb, gchar * default_name, gboolean do_correct)
{
	struct sockaddr_in sname;
	int len = sizeof(struct sockaddr_in);
	struct hostent *host_entry;

	if (do_correct) {
		getsockname(psb->sock, (struct sockaddr *) (&sname), &len);
		DEBUG(5) debugf("socket: name.sin_addr = %s\n", inet_ntoa(sname.sin_addr));
		host_entry = gethostbyaddr((const char *) &(sname.sin_addr), sizeof(sname.sin_addr), AF_INET);
		if (host_entry) {
			psb->helo_name = g_strdup(host_entry->h_name);
		} else {
			/* we failed to look up our own name. Instead of giving our local hostname,
			   we may give our IP number to show the server that we are at least
			   willing to be honest. For the really picky ones. */
			DEBUG(5) debugf("failed to look up own host name.\n");
			psb->helo_name = g_strdup_printf("[%s]", inet_ntoa(sname.sin_addr));
		}
		DEBUG(5) debugf("helo_name = %s\n", psb->helo_name);
	}
	if (psb->helo_name == NULL) {
		psb->helo_name = g_strdup(default_name);
	}
	return psb->helo_name;
}

#ifdef ENABLE_AUTH

gboolean
set_auth(smtp_base * psb, gchar * name, gchar * login, gchar * secret)
{
	if ((strcasecmp(name, "CRAM-MD5") == 0) || (strcasecmp(name, "LOGIN") == 0)) {
		psb->auth_name = g_strdup(name);
		psb->auth_login = g_strdup(login);
		psb->auth_secret = g_strdup(secret);

		return TRUE;
	}
	return FALSE;
}

#endif

static smtp_base*
create_smtpbase(gint sock)
{
	gint dup_sock;

	smtp_base *psb = (smtp_base *) g_malloc(sizeof(smtp_base));

	psb->sock = sock;

	psb->use_size = FALSE;
	psb->use_pipelining = FALSE;
	psb->use_auth = FALSE;

	psb->max_size = 0;
	psb->auth_names = NULL;

	psb->buffer = (gchar *) g_malloc(SMTP_BUF_LEN);

	dup_sock = dup(sock);
	psb->out = fdopen(sock, "w");
	psb->in = fdopen(dup_sock, "r");

	psb->error = smtp_ok;

	psb->helo_name = NULL;

	psb->auth_name = psb->auth_login = psb->auth_secret = NULL;

	return psb;
}

static gboolean
read_response(smtp_base * psb, int timeout)
{
	gint buf_pos = 0;
	gchar code[5];
	gint i, len;

	do {
		len = read_sockline(psb->in, &(psb->buffer[buf_pos]), SMTP_BUF_LEN - buf_pos, timeout, READSOCKL_CHUG);
		if (len == -3) {
			psb->error = smtp_timeout;
			return FALSE;
		} else if (len == -2) {
			psb->error = smtp_syntax;
			return FALSE;
		} else if (len == -1) {
			psb->error = smtp_eof;
			return FALSE;
		}
		for (i = 0; i < 4; i++)
			code[i] = psb->buffer[buf_pos + i];
		code[i] = '\0';
		psb->last_code = atoi(code);

		buf_pos += len;

	} while (code[3] == '-');
	if (psb->buffer) {
		DEBUG(4) debugf("S: %s\n", psb->buffer);
	}

	return TRUE;
}

static gboolean
check_response(smtp_base * psb, gboolean after_data)
{
	char c = psb->buffer[0];

	if (((c == '2') && !after_data) || ((c == '3') && after_data)) {
		psb->error = smtp_ok;
		DEBUG(6) debugf("response OK:'%s' after_data = %d\n", psb->buffer, (int) after_data);
		return TRUE;
	} else {
		if (c == '4')
			psb->error = smtp_trylater;
		else if (c == '5')
			psb->error = smtp_fail;
		else
			psb->error = smtp_syntax;
		DEBUG(6) debugf("response failure:'%s' after_data = %d\n", psb->buffer, (int) after_data);
		return FALSE;
	}
}

static gchar*
get_response_arg(gchar * response)
{
	gchar buf[SMTP_BUF_LEN];
	gchar *p = response, *q = buf;

	while (*p && (*p != '\n') && isspace(*p))
		p++;
	if (*p && (*p != '\n')) {
		while (*p && (*p != '\n') && (*p != '\r') && (q < buf + SMTP_BUF_LEN - 1))
			*(q++) = *(p++);
		*q = '\0';
		return g_strdup(buf);
	}
	return NULL;
}

static gboolean
check_helo_response(smtp_base * psb)
{
	gchar *ptr;

	if (!check_response(psb, FALSE))
		return FALSE;

	if (psb->last_code == 220) {
		logwrite(LOG_NOTICE, "received a 220 greeting after sending EHLO,\n");
		logwrite(LOG_NOTICE, "please remove `instant_helo' from your route config\n");
		/* read the next response, cause that's the actual helo response */
		if (!read_response(psb, SMTP_CMD_TIMEOUT) || !check_response(psb, FALSE)) {
			return FALSE;
		}
	}

	ptr = psb->buffer;

	while (*ptr) {
		if (strncasecmp(&(ptr[4]), "SIZE", 4) == 0) {
			gchar *arg;
			psb->use_size = TRUE;
			arg = get_response_arg(&(ptr[8]));
			if (arg) {
				psb->max_size = atoi(arg);
				g_free(arg);
			}
		}

		if (strncasecmp(&(ptr[4]), "PIPELINING", 10) == 0)
			psb->use_pipelining = TRUE;

		if (strncasecmp(&(ptr[4]), "AUTH", 4) == 0) {
			if ((ptr[8] == ' ') || (ptr[8] == '=') || (ptr[8] == '\t')) {  /* not sure about '\t' */
				gchar *arg;
				psb->use_auth = TRUE;
				arg = get_response_arg(&(ptr[9]));  /* after several years I finally learnt to count */
				if (arg) {
					psb->auth_names = g_strsplit(arg, " ", 0);
					g_free(arg);

					DEBUG(4) {
						gint i = 0;
						debugf("in check_helo_response()\n");
						while (psb->auth_names[i]) {
							debugf("  offered AUTH %s\n", psb->auth_names[i]);
							i++;
						}
					}
				}
			}
		}

		while (*ptr != '\n')
			ptr++;
		ptr++;
	}

	DEBUG(4) {
		debugf("  %s\n", psb->use_size ? "uses SIZE" : "no size");
		debugf("  %s\n", psb->use_pipelining ? "uses PIPELINING" : "no pipelining");
		debugf("  %s\n", psb->use_auth ? "uses AUTH" : "no auth");
	}

	return TRUE;
}

/*
We first try EHLO, but if it fails HELO in a second fall back try.
This is what is requested by RFC 2821 (sec 3.2):

	Once the server has sent the welcoming message and
	the client has received it, the client normally sends
	the EHLO command to the server, [...]
	For a particular connection attempt, if the server
	returns a "command not recognized" response to EHLO,
	the client SHOULD be able to fall back and send HELO.

Up to and including version 0.3.0 masqmail used ESMTP only if the
string ``ESMTP'' appeared within the server's greeting message. This
made it impossible to use AUTH with servers that would send odd
greeting messages.
*/
static gboolean
smtp_helo(smtp_base * psb, gchar * helo)
{
	fprintf(psb->out, "EHLO %s\r\n", helo);
	fflush(psb->out);
	DEBUG(4) debugf("C: EHLO %s\r\n", helo);

	if (!read_response(psb, SMTP_CMD_TIMEOUT)) {
		return FALSE;
	}
	if (check_helo_response(psb)) {
		DEBUG(4) debugf("uses esmtp\n");
		return TRUE;
	}

	if (psb->error != smtp_fail) {
		return FALSE;
	}

	/* our guess that server understands EHLO could have been wrong,
	   try again with HELO */

	fprintf(psb->out, "HELO %s\r\n", helo);
	fflush(psb->out);
	DEBUG(4) debugf("C: HELO %s\r\n", helo);

	if (!read_response(psb, SMTP_CMD_TIMEOUT)) {
		return FALSE;
	}
	if (check_helo_response(psb)) {
		DEBUG(4) debugf("uses smtp\n");
		return TRUE;
	}

	/* what sort of server ist THAT ?!  give up... */
	return FALSE;
}

static void
smtp_cmd_mailfrom(smtp_base * psb, address * return_path, guint size)
{
	if (psb->use_size) {
		fprintf(psb->out, "MAIL FROM:%s SIZE=%d\r\n", addr_string(return_path), size);
		fflush(psb->out);

		DEBUG(4) debugf("C: MAIL FROM:%s SIZE=%d\r\n", addr_string(return_path), size);

	} else {
		fprintf(psb->out, "MAIL FROM:%s\r\n", addr_string(return_path));
		fflush(psb->out);

		DEBUG(4) debugf("C: MAIL FROM:%s\r\n", addr_string(return_path));
	}
}

static void
smtp_cmd_rcptto(smtp_base * psb, address * rcpt)
{
	fprintf(psb->out, "RCPT TO:%s\r\n", addr_string(rcpt));
	fflush(psb->out);
	DEBUG(4) debugf("C: RCPT TO:%s\n", addr_string(rcpt));
}

static void
send_data_line(smtp_base * psb, gchar * data)
{
	/* According to RFC 821 each line should be terminated with CRLF.
	   Since a dot on a line itself marks the end of data, each line
	   beginning with a dot is prepended with another dot.
	 */
	gchar *ptr;
	gboolean new_line = TRUE;  /* previous versions assumed that each item was exactly one line.
	                              This is no longer the case */

	ptr = data;
	while (*ptr) {
		int c = (int) (*ptr);
		if (c == '.' && new_line) {
			/* dot-stuffing */
			putc('.', psb->out);
		}
		if (c == '\n') {
			/* CRLF line terminators */
			putc('\r', psb->out);
			putc('\n', psb->out);
			new_line = TRUE;
		} else {
			putc(c, psb->out);
			new_line = FALSE;
		}
		ptr++;
	}
}

static void
send_header(smtp_base * psb, GList * hdr_list)
{
	GList *node;
	gint num_hdrs = 0;

	/* header */
	if (hdr_list) {
		foreach(hdr_list, node) {
			if (node->data) {
				header *hdr = (header *) (node->data);
				if (hdr->header) {
					send_data_line(psb, hdr->header);
					num_hdrs++;
				}
			}
		}
	}

	/* empty line separating headers from data: */
	putc('\r', psb->out);
	putc('\n', psb->out);

	DEBUG(4) debugf("sent %d headers\n", num_hdrs);
}

static void
send_data(smtp_base * psb, message * msg)
{
	GList *node;
	gint num_lines = 0;

	/* data */
	if (msg->data_list) {
		for (node = g_list_first(msg->data_list); node; node = g_list_next(node)) {
			if (node->data) {
				send_data_line(psb, node->data);
				num_lines++;
			}
		}
	}

	DEBUG(4) debugf("sent %d lines of data\n", num_lines);

	fprintf(psb->out, ".\r\n");
	fflush(psb->out);
	DEBUG(4) debugf("C: .\n");
}

void
smtp_out_mark_rcpts(smtp_base * psb, GList * rcpt_list)
{
	GList *rcpt_node;
	for (rcpt_node = g_list_first(rcpt_list); rcpt_node; rcpt_node = g_list_next(rcpt_node)) {
		address *rcpt = (address *) (rcpt_node->data);

		addr_unmark_delivered(rcpt);

		if ((psb->error == smtp_trylater) || (psb->error == smtp_timeout) || (psb->error == smtp_eof)) {
			addr_mark_defered(rcpt);
		} else {
			addr_mark_failed(rcpt);
		}
	}
}

void
smtp_out_log_failure(smtp_base * psb, message * msg)
{
	gchar *err_str;

	if (psb->error == smtp_timeout)
		err_str = g_strdup("connection timed out.");
	else if (psb->error == smtp_eof)
		err_str = g_strdup("connection terminated prematurely.");
	else if (psb->error == smtp_syntax)
		err_str = g_strdup_printf("got unexpected response: %s", psb->buffer);
	else if (psb->error == smtp_cancel)
		err_str = g_strdup("delivery was canceled.\n");
	else
		/* error message should still be in the buffer */
		err_str = g_strdup_printf("failed: %s\n", psb->buffer);

	if (msg == NULL)
		logwrite(LOG_NOTICE, "host=%s %s\n", psb->remote_host, err_str);
	else
		logwrite(LOG_NOTICE, "%s == host=%s %s\n", msg->uid, psb->remote_host, err_str);

	g_free(err_str);
}

smtp_base*
smtp_out_open(gchar * host, gint port, GList * resolve_list)
{
	smtp_base *psb;
	gint sock;
	mxip_addr *addr;

	DEBUG(5) debugf("smtp_out_open entered, host = %s\n", host);

	if ((addr = connect_resolvelist(&sock, host, port, resolve_list))) {
		/* create structure to hold status data: */
		psb = create_smtpbase(sock);
		psb->remote_host = addr->name;

		DEBUG(5) {
			struct sockaddr_in name;
			int len = sizeof(struct sockaddr);
			getsockname(sock, (struct sockaddr *) (&name), &len);
			debugf("socket: name.sin_addr = %s\n", inet_ntoa(name.sin_addr));
		}
		return psb;
	} else {
		DEBUG(5) debugf("connect_resolvelist failed: %s %s\n", strerror(errno), hstrerror(h_errno));
	}

	return NULL;
}

smtp_base*
smtp_out_open_child(gchar * cmd, char* host)
{
	smtp_base *psb;
	gint sock;

	DEBUG(5) debugf("smtp_out_open_child entered, cmd = %s\n", cmd);
	psb->remote_host = host;
	sock = child(cmd);
	if (sock > 0) {
		psb = create_smtpbase(sock);
		psb->remote_host = NULL;

		return psb;
	}

	return NULL;
}

gboolean
smtp_out_rset(smtp_base * psb)
{
	gboolean ok;

	fprintf(psb->out, "RSET\r\n");
	fflush(psb->out);
	DEBUG(4) debugf("C: RSET\n");

	if ((ok = read_response(psb, SMTP_CMD_TIMEOUT)))
		if (check_response(psb, FALSE))
			return TRUE;

	smtp_out_log_failure(psb, NULL);

	return FALSE;
}

#ifdef ENABLE_AUTH

static gboolean
smtp_out_auth_cram_md5(smtp_base * psb)
{
	gboolean ok = FALSE;

	fprintf(psb->out, "C: AUTH CRAM-MD5\r\n");
	fflush(psb->out);
	DEBUG(4) debugf("AUTH CRAM-MD5\n");
	if ((ok = read_response(psb, SMTP_CMD_TIMEOUT))) {
		if ((ok = check_response(psb, TRUE))) {
			gchar *chall64 = get_response_arg(&(psb->buffer[4]));
			gint chall_size;
			gchar *chall = base64_decode(chall64, &chall_size);
			guchar digest[16], *reply64, *reply;
			gchar digest_string[33];
			gint i;

			DEBUG(5) debugf("smtp_out_auth_cram_md5():\n");
			DEBUG(5) debugf("  encoded challenge = %s\n", chall64);
			DEBUG(5) debugf("  decoded challenge = %s, size = %d\n", chall, chall_size);
			DEBUG(5) debugf("  secret = %s\n", psb->auth_secret);

			hmac_md5(chall, chall_size, psb->auth_secret, strlen(psb->auth_secret), digest);
			for (i = 0; i < 16; i++)
				sprintf(&(digest_string[i + i]), "%02x", (unsigned int) (digest[i]));
			digest_string[32] = '\0';

			DEBUG(5) debugf("  digest = %s\n", digest_string);

			reply = g_strdup_printf("%s %s", psb->auth_login, digest_string);
			DEBUG(5) debugf("  unencoded reply = %s\n", reply);

			reply64 = base64_encode(reply, strlen(reply));
			DEBUG(5) debugf("  encoded reply = %s\n", reply64);

			fprintf(psb->out, "%s\r\n", reply64);
			fflush(psb->out);
			DEBUG(6) debugf("  reply64 = %s\n", reply64);
			DEBUG(6) debugf("C: %s\n", reply64);

			if ((ok = read_response(psb, SMTP_CMD_TIMEOUT)))
				ok = check_response(psb, FALSE);

			g_free(reply64);
			g_free(reply);
			g_free(chall);
			g_free(chall64);
		}
	}
	return ok;
}

static gboolean
smtp_out_auth_login(smtp_base * psb)
{
	gboolean ok = FALSE;
	fprintf(psb->out, "AUTH LOGIN\r\n");
	fflush(psb->out);
	DEBUG(4) debugf("C: AUTH LOGIN\r\n");
	if ((ok = read_response(psb, SMTP_CMD_TIMEOUT))) {
		if ((ok = check_response(psb, TRUE))) {
			gchar *resp64;
			guchar *resp;
			gint resp_size;
			gchar *reply64;

			DEBUG(5) debugf("smtp_out_auth_login():\n");
			resp64 = get_response_arg(&(psb->buffer[4]));
			DEBUG(5) debugf("  encoded response = `%s'\n", resp64);
			resp = base64_decode(resp64, &resp_size);
			g_free(resp64);
			DEBUG(5) debugf("  decoded response = `%s', size = %d\n", resp, resp_size);
			g_free(resp);
			reply64 = base64_encode(psb->auth_login, strlen(psb->auth_login));
			fprintf(psb->out, "%s\r\n", reply64);
			fflush(psb->out);
			DEBUG(6) debugf("C: %s\n", reply64);
			g_free(reply64);
			if ((ok = read_response(psb, SMTP_CMD_TIMEOUT))) {
				if ((ok = check_response(psb, TRUE))) {
					resp64 = get_response_arg(&(psb->buffer[4]));
					DEBUG(5) debugf("  encoded response = `%s'\n", resp64);
					resp = base64_decode(resp64, &resp_size);
					g_free(resp64);
					DEBUG(5) debugf("  decoded response = `%s', size = %d\n", resp, resp_size);
					g_free(resp);
					reply64 = base64_encode(psb->auth_secret, strlen(psb->auth_secret));
					fprintf(psb->out, "%s\r\n", reply64);
					fflush(psb->out);
					DEBUG(6) debugf("C: %s\n", reply64);
					g_free(reply64);
					if ((ok = read_response(psb, SMTP_CMD_TIMEOUT)))
						ok = check_response(psb, FALSE);
				}
			}
		}
	}
	return ok;
}

gboolean
smtp_out_auth(smtp_base * psb)
{
	gboolean ok = FALSE;
	gint i = 0;
	while (psb->auth_names[i]) {
		if (strcasecmp(psb->auth_names[i], psb->auth_name) == 0)
			break;
		i++;
	}
	if (psb->auth_names[i]) {
		if (strcasecmp(psb->auth_name, "cram-md5") == 0) {
			smtp_out_auth_cram_md5(psb);
		} else if (strcasecmp(psb->auth_name, "login") == 0) {
			smtp_out_auth_login(psb);
		} else {
			logwrite(LOG_ERR, "auth method %s not supported\n", psb->auth_name);
		}
	} else {
		logwrite(LOG_ERR, "no auth method %s found.\n", psb->auth_name);
	}
	return ok;
}

#endif

gboolean
smtp_out_init(smtp_base * psb, gboolean instant_helo)
{
	gboolean ok;

	logwrite(LOG_INFO, "smtp_out_init(): instant_helo:%d\n", instant_helo);

	if (!instant_helo) {
		if ((ok = read_response(psb, SMTP_INITIAL_TIMEOUT))) {
			ok = check_response(psb, FALSE);
		}
		if (!ok) {
			smtp_out_log_failure(psb, NULL);
			return ok;
		}
	}

	if ((ok = smtp_helo(psb, psb->helo_name))) {
#ifdef ENABLE_AUTH
		if (psb->auth_name && psb->use_auth) {
			/* we completely disregard the response of server here. If
			   authentication fails, the server will complain later
			   anyway. I know, this is not polite... */
			smtp_out_auth(psb);
		}
#endif
	}
	if (!ok)
		smtp_out_log_failure(psb, NULL);
	return ok;
}

gint
smtp_out_msg(smtp_base * psb, message * msg, address * return_path, GList * rcpt_list, GList * hdr_list)
{
	gint i, size;
	gboolean ok = TRUE;
	int rcpt_cnt;
	int rcpt_accept = 0;

	DEBUG(5) debugf("smtp_out_msg entered\n");

	/* defaults: */
	if (return_path == NULL)
		return_path = msg->return_path;
	if (hdr_list == NULL)
		hdr_list = msg->hdr_list;
	if (rcpt_list == NULL)
		rcpt_list = msg->rcpt_list;
	rcpt_cnt = g_list_length(rcpt_list);

	size = msg_calc_size(msg, TRUE);

	/* respect maximum size given by server: */
	if ((psb->max_size > 0) && (size > psb->max_size)) {
		logwrite(LOG_WARNING, "%s == host=%s message size (%d) > "
		                      "fixed maximum message size of server (%d)",
		         msg->uid, psb->remote_host, size, psb->max_size);
		psb->error = smtp_cancel;
		ok = FALSE;
	}

	if (ok) {
		/* pretend the message is a bit larger,
		   just in case the size calculation is buggy */
		smtp_cmd_mailfrom(psb, return_path, psb->use_size ? size+SMTP_SIZE_ADD : 0);

		if (!psb->use_pipelining) {
			if ((ok = read_response(psb, SMTP_CMD_TIMEOUT)))
				ok = check_response(psb, FALSE);
		}
	}
	if (ok) {
		GList *rcpt_node;
		rcpt_accept = 0;

		for (rcpt_node = g_list_first(rcpt_list); rcpt_node != NULL; rcpt_node = g_list_next(rcpt_node)) {
			address *rcpt = (address *) (rcpt_node->data);
			smtp_cmd_rcptto(psb, rcpt);
			if (!psb->use_pipelining) {
				if ((ok = read_response(psb, SMTP_CMD_TIMEOUT)))
					if (check_response(psb, FALSE)) {
						rcpt_accept++;
						addr_mark_delivered(rcpt);
					} else {
						/* if server returned an error for one recp. we
						   may still try the others. But if it is a timeout, eof
						   or unexpected response, it is more serious and we should
						   give up. */
						if ((psb->error != smtp_trylater) && (psb->error != smtp_fail)) {
							ok = FALSE;
							break;
						} else {
							logwrite(LOG_NOTICE, "%s == %s host=%s failed: %s\n",
							         msg->uid, addr_string(rcpt), psb->remote_host, psb->buffer);
							if (psb->error == smtp_trylater) {
								addr_mark_defered(rcpt);
							} else {
								addr_mark_failed(rcpt);
							}
						}
				} else
					break;
			}
		}

		/* There is no point in going on if no recp.s were accpted.
		   But we can check that at this point only if not pipelining: */
		ok = (ok && (psb->use_pipelining || (rcpt_accept > 0)));
		if (ok) {

			fprintf(psb->out, "DATA\r\n");
			fflush(psb->out);

			DEBUG(4) debugf("C: DATA\r\n");

			if (psb->use_pipelining) {
				/* the first pl'ed command was MAIL FROM
				   the last was DATA, whose response can be handled by the 'normal' code
				   all in between were RCPT TO:
				 */
				/* response to MAIL FROM: */
				if ((ok = read_response(psb, SMTP_CMD_TIMEOUT))) {
					if ((ok = check_response(psb, FALSE))) {

						/* response(s) to RCPT TO:
						   this is very similar to the sequence above for no pipeline
						 */
						for (i = 0; i < rcpt_cnt; i++) {
							if ((ok = read_response(psb, SMTP_CMD_TIMEOUT))) {
								address *rcpt = g_list_nth_data(rcpt_list, i);
								if (check_response(psb, FALSE)) {
									rcpt_accept++;
									addr_mark_delivered(rcpt);
								} else {
									/* if server returned an error 4xx or 5xx for one recp. we
									   may still try the others. But if it is a timeout, eof
									   or unexpected response, it is more serious and we
									   should give up. */
									if ((psb->error != smtp_trylater) &&
										(psb->error != smtp_fail)) {
										ok = FALSE;
										break;
									} else {
										logwrite(LOG_NOTICE, "%s == %s host=%s failed: %s\n", msg->uid,
										         addr_string(rcpt), psb->remote_host, psb->buffer);
										if (psb->error == smtp_trylater) {
											addr_mark_defered(rcpt);
										} else {
											addr_mark_failed(rcpt);
										}
									}
								}
							} else {
								DEBUG(5) debugf("check_response failed after RCPT TO\n");
								break;
							}
						}
						if (rcpt_accept == 0)
							ok = FALSE;
					} else {
						DEBUG(5) debugf("check_response failed after MAIL FROM\n");
					}
				} else {
					DEBUG(5)
						debugf("read_response failed after MAIL FROM\n");
				}
			}

			/* if(psb->use_pipelining) */
			/* response to the DATA cmd */
			if (ok) {
				if (read_response(psb, SMTP_DATA_TIMEOUT)) {
					if (check_response(psb, TRUE)) {
						send_header(psb, hdr_list);
						send_data(psb, msg);

						if (read_response(psb, SMTP_FINAL_TIMEOUT))
							ok = check_response(psb, FALSE);
					}
				}
			}
		}
	}

	DEBUG(5) {
		debugf("smtp_out_msg():\n");
		debugf("  psb->error = %d\n", psb->error);
		debugf("  ok = %d\n", ok);
		debugf("  rcpt_accept = %d\n", rcpt_accept);
	}

	if (psb->error == smtp_ok) {
		GList *rcpt_node;
		for (rcpt_node = g_list_first(rcpt_list); rcpt_node; rcpt_node = g_list_next(rcpt_node)) {
			address *rcpt = (address *) (rcpt_node->data);
			if (addr_is_delivered(rcpt))
				logwrite(LOG_NOTICE, "%s => %s host=%s\n",
				         msg->uid, addr_string(rcpt), psb->remote_host);
		}
	} else {
		/* if something went wrong,
		   we have to unmark the rcpts prematurely marked as delivered
		   and mark the status */
		smtp_out_mark_rcpts(psb, rcpt_list);

		/* log the failure: */
		smtp_out_log_failure(psb, msg);
	}
	return rcpt_accept;
}

gboolean
smtp_out_quit(smtp_base * psb)
{
	fprintf(psb->out, "QUIT\r\n");
	fflush(psb->out);

	DEBUG(4) debugf("C: QUIT\n");

	signal(SIGALRM, SIG_DFL);

	return TRUE;
}

gint
smtp_deliver(gchar * host, gint port, GList * resolve_list, message * msg, address * return_path, GList * rcpt_list)
{
	smtp_base *psb;
	smtp_error err;

	DEBUG(5) debugf("smtp_deliver entered\n");

	if (return_path == NULL)
		return_path = msg->return_path;

	if ((psb = smtp_out_open(host, port, resolve_list))) {
		set_heloname(psb, return_path->domain, TRUE);
		/* initiate connection, send message and quit: */
		if (smtp_out_init(psb, FALSE)) {
			smtp_out_msg(psb, msg, return_path, rcpt_list, NULL);
			if (psb->error == smtp_ok || (psb->error == smtp_fail) || (psb->error == smtp_trylater)
			    || (psb->error == smtp_syntax) || (psb->error == smtp_cancel))
				smtp_out_quit(psb);
		}

		err = psb->error;
		destroy_smtpbase(psb);

		return err;
	}
	return -1;
}
