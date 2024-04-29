// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  smtp_out.c
*/

/*
**  I always forget these rfc numbers:
**  RFC 821  (SMTP)
**  RFC 1869 (ESMTP)
**  RFC 1870 (ESMTP SIZE)
**  RFC 2197 (ESMTP PIPELINE)
**  RFC 2554 (ESMTP AUTH)
*/

#include "smtp_out.h"
#include "readsock.h"

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void
destroy_smtpbase(smtp_base *psb)
{
	fclose(psb->in);
	fclose(psb->out);

	g_free(psb->remote_host);
	g_free(psb->helo_name);
	g_free(psb->buffer);
	g_strfreev(psb->auth_names);

	g_free(psb->auth_name);
	g_free(psb->auth_login);
	g_free(psb->auth_secret);

	g_free(psb);
}

gchar*
set_heloname(smtp_base *psb, gchar *default_name, gboolean do_correct)
{
	struct sockaddr_in sname;
	socklen_t len = sizeof(struct sockaddr_in);
	struct hostent *host_entry;

	if (do_correct) {
		getsockname(fileno(psb->out), (struct sockaddr *) (&sname), &len);
		DEBUG(5) debugf("socket: name.sin_addr = %s\n", inet_ntoa(sname.sin_addr));
		host_entry = gethostbyaddr((const char *) &(sname.sin_addr), sizeof(sname.sin_addr), AF_INET);
		if (host_entry) {
			psb->helo_name = g_strdup(host_entry->h_name);
		} else {
			/*
			**  we failed to look up our own name. Instead of
			**  giving our local hostname, we may give our IP
			**  number to show the server that we are at least
			**  willing to be honest. For the really picky ones.
			*/
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
set_auth(smtp_base *psb, gchar *name, gchar *login, gchar *secret)
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

	smtp_base *psb = g_malloc0(sizeof(smtp_base));

	psb->buffer = (gchar *) g_malloc(SMTP_BUF_LEN);

	dup_sock = dup(sock);
	psb->out = fdopen(sock, "w");
	psb->in = fdopen(dup_sock, "r");

	return psb;
}

static gboolean
read_response(smtp_base *psb, int timeout, const char *cmd)
{
	gint buf_pos = 0;
	gchar code[5];
	gint i, len;

	do {
		len = read_sockline(psb->in, &(psb->buffer[buf_pos]), SMTP_BUF_LEN - buf_pos, timeout, READSOCKL_CHUG);
		if (len == -3) {
			psb->error = smtp_timeout;
			goto fail;
		} else if (len == -2) {
			psb->error = smtp_syntax;
			goto fail;
		} else if (len == -1) {
			psb->error = smtp_eof;
			goto fail;
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

  fail:
	// a more informative info message is logged later.
	DEBUG(5) debugf("read_response() failed after %s\n", cmd);
	return FALSE;
}

static gboolean
check_response(smtp_base *psb, gboolean after_data, const char *cmd)
{
	char c = psb->buffer[0];

	if (((c == '2') && !after_data) || ((c == '3') && after_data)) {
		psb->error = smtp_ok;
		DEBUG(6) debugf("response to %s OK: '%s' after_data = %d\n",
		                cmd, psb->buffer, (int) after_data);
		return TRUE;
	} else {
		if (c == '4')
			psb->error = smtp_trylater;
		else if (c == '5')
			psb->error = smtp_fail;
		else
			psb->error = smtp_syntax;
		DEBUG(6) debugf("response to %s bad: '%s' after_data = %d\n",
		                cmd, psb->buffer, (int) after_data);
		return FALSE;
	}
}

static gboolean
read_check_response(smtp_base *psb, int timeout, gboolean after_data, const char *cmd)
{
	return read_response(psb, timeout, cmd) && check_response(psb, after_data, cmd);
}

static gchar*
get_response_arg(gchar *response)
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
check_helo_response(smtp_base *psb, const char *cmd)
{
	gchar *ptr;

	if (!check_response(psb, FALSE, cmd))
		return FALSE;

	if (psb->last_code == 220) {
		logwrite(LOG_NOTICE, "received a 220 greeting after sending EHLO,\n");
		logwrite(LOG_NOTICE, "please remove `instant_helo' from your route config\n");
		/* read the next response, cause that's the actual helo response */
		if (!read_check_response(psb, SMTP_CMD_TIMEOUT, FALSE, cmd)) {
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
		} else if (strncasecmp(&(ptr[4]), "PIPELINING", 10) == 0) {
			psb->use_pipelining = TRUE;
		} else if (strncasecmp(&(ptr[4]), "AUTH", 4) == 0) {
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

#ifdef __GNUC__
# define smtp_cmd(psb, fmt, ...) \
	do { \
		DEBUG(4) debugf("C: " fmt "\n", ##__VA_ARGS__); \
		fprintf(psb->out, fmt "\r\n", ##__VA_ARGS__); \
		fflush(psb->out); \
	} while (0)
#else  // hope for C23
# define smtp_cmd(psb, fmt, ...) \
	do { \
		DEBUG(4) debugf("C: " fmt "\n" __VA_OPT__(,) __VA_ARGS__); \
		fprintf(psb->out, fmt "\r\n" __VA_OPT__(,) __VA_ARGS__); \
		fflush(psb->out); \
	} while (0)
#endif

/*
**  We first try EHLO, but if it fails HELO in a second fall back try.
**  This is what is requested by RFC 2821 (sec 3.2):
**
**      Once the server has sent the welcoming message and
**      the client has received it, the client normally sends
**      the EHLO command to the server, [...]
**      For a particular connection attempt, if the server
**      returns a "command not recognized" response to EHLO,
**      the client SHOULD be able to fall back and send HELO.
**
**  Up to and including version 0.3.0 masqmail used ESMTP only if the
**  string ``ESMTP'' appeared within the server's greeting message. This
**  made it impossible to use AUTH with servers that would send odd
**  greeting messages.
*/
static gboolean
smtp_helo(smtp_base *psb, gchar *helo)
{
	smtp_cmd(psb, "EHLO %s", helo);

	if (!read_response(psb, SMTP_CMD_TIMEOUT, "EHLO")) {
		return FALSE;
	}
	if (check_helo_response(psb, "EHLO")) {
		DEBUG(4) debugf("uses esmtp\n");
		return TRUE;
	}

	if (psb->error != smtp_fail) {
		return FALSE;
	}

	/*
	**  our guess that server understands EHLO could have been wrong,
	**  try again with HELO
	*/
	smtp_cmd(psb, "HELO %s", helo);

	if (!read_response(psb, SMTP_CMD_TIMEOUT, "HELO")) {
		return FALSE;
	}
	if (check_helo_response(psb, "HELO")) {
		DEBUG(4) debugf("uses smtp\n");
		return TRUE;
	}

	/* what sort of server ist THAT ?!  give up... */
	return FALSE;
}

static void
smtp_cmd_mailfrom(smtp_base *psb, address *return_path, gssize size)
{
	if (psb->use_size) {
		smtp_cmd(psb, "MAIL FROM:<%s> SIZE=%" G_GSSIZE_FORMAT, return_path->address, size);
	} else {
		smtp_cmd(psb, "MAIL FROM:<%s>", return_path->address);
	}
}

static void
smtp_cmd_rcptto(smtp_base *psb, address *rcpt)
{
	smtp_cmd(psb, "RCPT TO:<%s>", rcpt->address);
}

static void
send_data_line(smtp_base *psb, gchar *data)
{
	/*
	**  According to RFC 821 each line should be terminated with CRLF.
	**  Since a dot on a line itself marks the end of data, each line
	**  beginning with a dot is prepended with another dot.
	*/
	gchar *ptr;
	gboolean new_line = TRUE;  /* previous versions assumed that each item was exactly one line.  This is no longer the case */

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
send_header(smtp_base *psb, GList *hdr_list)
{
	gint num_hdrs = 0;

	/* header */
	foreach (header *hdr, hdr_list) {
		send_data_line(psb, hdr->header);
		num_hdrs++;
	}

	/* empty line separating headers from data: */
	putc('\r', psb->out);
	putc('\n', psb->out);

	DEBUG(4) debugf("sent %d headers\n", num_hdrs);
}

static void
send_data(smtp_base *psb, message *msg)
{
	gint num_lines = 0;

	/* data */
	foreach (gchar *line, msg->data_list) {
		send_data_line(psb, line);
		num_lines++;
	}

	DEBUG(4) debugf("sent %d lines of data\n", num_lines);

	smtp_cmd(psb, ".");
}

void
smtp_out_mark_rcpts(smtp_base *psb, GList *rcpt_list)
{
	foreach (recipient *rcpt, rcpt_list) {
		addr_unmark_delivered(rcpt);

		if ((psb->error == smtp_trylater) || (psb->error == smtp_timeout) || (psb->error == smtp_eof)) {
			addr_mark_defered(rcpt);
		} else {
			addr_mark_failed(rcpt);
		}
	}
}

static void
smtp_out_log_failure(smtp_base *psb, message *msg, gchar **err_msg)
{
	const gchar *wrap_str = psb->is_wrapped ? " (via wrapper)" : "";

	const gchar *err_str;
	const gchar *err_sep_log = "", *err_sep_mail = ".", *err_pay = "";
	if (psb->error == smtp_timeout) {
		err_str = "Connection timed out";
	} else if (psb->error == smtp_eof) {
		err_str = "Connection terminated prematurely";
	} else if (psb->error == smtp_cancel) {
		err_str = "Message size exceeds limit";
	} else {
		err_str = "Unexpected response";
		err_sep_log = ": ";
		err_sep_mail = ":\n\t";
		/* error message should still be in the buffer */
		err_pay = psb->buffer;
	}

	if (msg == NULL) {
		logwrite(LOG_INFO, "host=%s%s %s%s%s\n",
		         psb->remote_host, wrap_str, err_str, err_sep_log, err_pay);
	} else {
		logwrite(LOG_INFO, "%s == host=%s%s %s%s%s\n",
		         msg->uid, psb->remote_host, wrap_str, err_str, err_sep_log, err_pay);
	}

	if (err_msg) {
		*err_msg = g_strdup_printf(
				"%s while connected to\n%s%s%s%s",
				err_str, psb->remote_host, wrap_str, err_sep_mail, err_pay);
	}
}

smtp_base*
smtp_out_open(gchar *host, gint port, GList *resolve_list, gchar **err_msg)
{
	smtp_base *psb;
	gint sock;
	mxip_addr *addr;

	DEBUG(5) debugf("smtp_out_open entered, host = %s\n", host);

	if (!(addr = connect_resolvelist(&sock, host, port, resolve_list, err_msg))) {
		return NULL;
	}

	psb = create_smtpbase(sock);
	psb->remote_host = addr->name;
	addr->name = NULL;
	destroy_mxip_addr(addr);

	DEBUG(5) {
		struct sockaddr_in name;
		socklen_t len = sizeof(struct sockaddr);
		getsockname(sock, (struct sockaddr *) &name, &len);
		debugf("socket: name.sin_addr = %s\n", inet_ntoa(name.sin_addr));
	}
	return psb;
}

smtp_base*
smtp_out_open_child(const gchar *host, gchar *cmd, gchar **err_msg)
{
	smtp_base *psb;

	DEBUG(5) debugf("smtp_out_open_child entered, cmd = %s\n", cmd);

	gchar **argv;
	GError *gerr = NULL;
	if (!g_shell_parse_argv(cmd, NULL, &argv, &gerr)) {
		loggerror(LOG_ERR, gerr, "failed to parse wrapper command");
		goto fail;
	}

	int pipe[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0) {
		logerrno(LOG_ERR, "socketpair");
		g_strfreev(argv);
		goto fail;
	}
	gboolean ok = g_spawn_async_with_fds(
			NULL /* workdir */, argv, NULL /* env */,
			G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_CHILD_INHERITS_STDERR,
			NULL, NULL, /* child setup */
			NULL /* pid */, pipe[0], pipe[0], -1, &gerr);
	g_strfreev(argv);
	close(pipe[0]);
	if (!ok) {
		loggerror(LOG_ERR, gerr, "failed to launch wrapper command");
		close(pipe[1]);
		goto fail;
	}
	psb = create_smtpbase(pipe[1]);
	psb->is_wrapped = TRUE;
	psb->remote_host = g_strdup(host);

	return psb;

  fail:
	*err_msg = g_strdup("Failed to launch connection wrapper");
	return NULL;
}

gboolean
smtp_out_rset(smtp_base *psb)
{
	smtp_cmd(psb, "RSET");

	if (read_check_response(psb, SMTP_CMD_TIMEOUT, FALSE, "RSET")) {
		return TRUE;
	}

	smtp_out_log_failure(psb, NULL, NULL);

	return FALSE;
}

#ifdef ENABLE_AUTH

static gboolean
smtp_out_auth_cram_md5(smtp_base *psb)
{
	smtp_cmd(psb, "AUTH CRAM-MD5");
	if (!read_check_response(psb, SMTP_CMD_TIMEOUT, TRUE, "AUTH CRAM-MD5")) {
		return FALSE;
	}

	gchar *chall64 = get_response_arg(&(psb->buffer[4]));
	gsize chall_size;
	guchar *chall = g_base64_decode(chall64, &chall_size);
	gchar *reply64, *reply;
	gchar *digest_string;
	DEBUG(5) {
		debugf("smtp_out_auth_cram_md5():\n");
		debugf("  encoded challenge = %s\n", chall64);
		debugf("  decoded challenge = %.*s, size = %" G_GSIZE_FORMAT "\n",
		       (int) chall_size, chall, chall_size);
		debugf("  secret = %s\n", psb->auth_secret);
	}
	digest_string = g_compute_hmac_for_data(G_CHECKSUM_MD5,
			(guchar*) psb->auth_secret, strlen(psb->auth_secret),
			chall, chall_size);
	DEBUG(5) debugf("  digest = %s\n", digest_string);
	reply = g_strdup_printf("%s %s", psb->auth_login, digest_string);
	DEBUG(5) debugf("  unencoded reply = %s\n", reply);
	g_free(digest_string);
	reply64 = g_base64_encode((guchar*) reply, strlen(reply));
	DEBUG(5) debugf("  encoded reply = %s\n", reply64);
	smtp_cmd(psb, "%s", reply64);
	g_free(reply64);
	g_free(reply);
	g_free(chall);
	g_free(chall64);

	return read_check_response(psb, SMTP_CMD_TIMEOUT, FALSE, "AUTH CRAM-MD5 (cont)");
}

static gboolean
smtp_out_auth_login(smtp_base *psb)
{
	smtp_cmd(psb, "AUTH LOGIN");
	if (!read_check_response(psb, SMTP_CMD_TIMEOUT, TRUE, "AUTH LOGIN")) {
		return FALSE;
	}

	gchar *resp64;
	guchar *resp;
	gsize resp_size;
	gchar *reply64;
	DEBUG(5) {
		debugf("smtp_out_auth_login():\n");
		resp64 = get_response_arg(&(psb->buffer[4]));
		debugf("  encoded response = `%s'\n", resp64);
		resp = g_base64_decode(resp64, &resp_size);
		g_free(resp64);
		debugf("  decoded response = `%.*s', size = %" G_GSIZE_FORMAT "\n",
		       (int) resp_size, resp, resp_size);
		g_free(resp);
	}
	reply64 = g_base64_encode((guchar*) psb->auth_login, strlen(psb->auth_login));
	smtp_cmd(psb, "%s", reply64);
	g_free(reply64);

	if (!read_check_response(psb, SMTP_CMD_TIMEOUT, TRUE, "AUTH LOGIN (cont 1)")) {
		return FALSE;
	}
	DEBUG(5) {
		resp64 = get_response_arg(&(psb->buffer[4]));
		debugf("  encoded response = `%s'\n", resp64);
		resp = g_base64_decode(resp64, &resp_size);
		g_free(resp64);
		debugf("  decoded response = `%.*s', size = %" G_GSIZE_FORMAT "\n",
		       (int) resp_size, resp, resp_size);
		g_free(resp);
	}
	reply64 = g_base64_encode((guchar*) psb->auth_secret, strlen(psb->auth_secret));
	smtp_cmd(psb, "%s", reply64);
	g_free(reply64);

	return read_check_response(psb, SMTP_CMD_TIMEOUT, FALSE, "AUTH LOGIN (cont 2)");
}

static gboolean
smtp_out_auth(smtp_base *psb)
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
smtp_out_init(smtp_base *psb, gboolean instant_helo, gchar **err_msg)
{
	DEBUG(1) debugf("smtp_out_init(): instant_helo=%d\n", instant_helo);

	if (!instant_helo) {
		if (!read_check_response(psb, SMTP_INITIAL_TIMEOUT, FALSE, "connect")) {
			goto fail;
		}
	}

	if (!smtp_helo(psb, psb->helo_name)) {
		goto fail;
	}
#ifdef ENABLE_AUTH
	if (psb->auth_name && psb->use_auth) {
		// we completely disregard the server's response here.
		// if authentication fails, the server will complain
		// later anyway. i know, this is not polite...
		smtp_out_auth(psb);
	}
#endif
	return TRUE;

  fail:
	smtp_out_log_failure(psb, NULL, err_msg);
	return FALSE;
}

static gboolean
smtp_out_rcptto_resp(smtp_base *psb, message *msg, recipient *rcpt, int *rcpt_accept)
{
	// if the server returned an error for one rcpt we may still
	// try the others. but if it is a timeout, eof or unexpected
	// response, it is more serious and we should give up.

	if (!read_response(psb, SMTP_CMD_TIMEOUT, "RCPT TO")) {
		return FALSE;
	}
	if (check_response(psb, FALSE, "RCPT TO")) {
		(*rcpt_accept)++;
		addr_mark_delivered(rcpt);
		return TRUE;
	}
	if (psb->error == smtp_trylater) {
		addr_mark_defered(rcpt);
	} else if (psb->error == smtp_fail) {
		addr_mark_failed(rcpt);
	} else {
		return FALSE;
	}
	logwrite(LOG_NOTICE, "%s == <%s> host=%s failed: %s\n",
	         msg->uid, rcpt->address->address, psb->remote_host, psb->buffer);
	return TRUE;
}

void
smtp_out_msg(smtp_base *psb, message *msg, address *return_path,
             GList *rcpt_list, GList *hdr_list, gchar **err_msg)
{
	gssize size;
	int rcpt_accept = 0;

	DEBUG(5) debugf("smtp_out_msg entered\n");

	/* defaults: */
	if (return_path == NULL)
		return_path = msg->return_path;
	if (hdr_list == NULL)
		hdr_list = msg->hdr_list;
	if (rcpt_list == NULL)
		rcpt_list = msg->rcpt_list;

	size = msg_calc_size(msg, TRUE);

	/* respect maximum size given by server: */
	if ((psb->max_size > 0) && (size > psb->max_size)) {
		logwrite(LOG_WARNING, "%s == host=%s message size (%" G_GSSIZE_FORMAT ") > "
		                      "fixed maximum message size of server (%" G_GSSIZE_FORMAT ")",
		         msg->uid, psb->remote_host, size, psb->max_size);
		psb->error = smtp_cancel;
		goto fail;
	}

	// pretend the message is a bit larger,
	// just in case the size calculation is buggy
	smtp_cmd_mailfrom(psb, return_path, psb->use_size ? size + SMTP_SIZE_ADD : 0);
	if (!psb->use_pipelining) {
		if (!read_check_response(psb, SMTP_CMD_TIMEOUT, FALSE, "MAIL FROM")) {
			goto fail;
		}
	}

	foreach (recipient *rcpt, rcpt_list) {
		smtp_cmd_rcptto(psb, rcpt->address);
		if (!psb->use_pipelining) {
			if (!smtp_out_rcptto_resp(psb, msg, rcpt, &rcpt_accept)) {
				goto fail;
			}
		}
	}

	// there is no point in going on if no recipients were accepted.
	// but we can check that at this point only if not pipelining:
	if (!psb->use_pipelining && !rcpt_accept) {
		goto fail;
	}

	smtp_cmd(psb, "DATA");

	if (psb->use_pipelining) {
		// the first pipelined command was MAIL FROM. the last was
		// DATA, whose response can be handled by the 'normal' code.
		// all commands in between were RCPT TO:
		if (!read_check_response(psb, SMTP_CMD_TIMEOUT, FALSE, "MAIL FROM")) {
			goto fail;
		}
		foreach (recipient *rcpt, rcpt_list) {
			if (!smtp_out_rcptto_resp(psb, msg, rcpt, &rcpt_accept)) {
				goto fail;
			}
		}
		if (!rcpt_accept) {
			goto fail;
		}
	}

	if (!read_check_response(psb, SMTP_DATA_TIMEOUT, TRUE, "DATA")) {
		goto fail;
	}
	send_header(psb, hdr_list);
	send_data(psb, msg);

	if (!read_check_response(psb, SMTP_FINAL_TIMEOUT, FALSE, "DATA (cont)")) {
		goto fail;
	}

	foreach (recipient *rcpt, rcpt_list) {
		if (addr_is_delivered(rcpt)) {
			logwrite(LOG_INFO, "%s => <%s> host=%s\n",
			         msg->uid, rcpt->address->address, psb->remote_host);
		}
	}
	return;

  fail:
	// if something went wrong, we have to unmark the recipients prematurely
	// marked as delivered, and set the actual status instead.
	smtp_out_mark_rcpts(psb, rcpt_list);

	smtp_out_log_failure(psb, msg, err_msg);
}

void
smtp_out_quit(smtp_base *psb)
{
	if (psb->error == smtp_timeout || psb->error == smtp_eof) {
		// connection is already dead anyway.
		return;
	}

	smtp_cmd(psb, "QUIT");
}
