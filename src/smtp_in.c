/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth
    Copyright (C) 2010 markus schnalke <meillo@marmaro.de>

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

#include "masqmail.h"
#include "readsock.h"

/*
  I always forget these rfc numbers:
  RFC 821  (SMTP)
  RFC 1869 (ESMTP)
  RFC 1870 (ESMTP SIZE)
  RFC 2197 (ESMTP PIPELINE)
  RFC 2554 (ESMTP AUTH)
*/

#ifdef ENABLE_SMTP_SERVER

smtp_cmd smtp_cmds[] = {
	{SMTP_HELO, "HELO",},
	{SMTP_EHLO, "EHLO",},
	{SMTP_MAIL_FROM, "MAIL FROM:",},
	{SMTP_RCPT_TO, "RCPT TO:",},
	{SMTP_DATA, "DATA",},
	{SMTP_QUIT, "QUIT",},
	{SMTP_RSET, "RSET",},
	{SMTP_NOOP, "NOOP",},
	{SMTP_HELP, "HELP"},
};

static smtp_cmd_id
get_id(const gchar * line)
{
	gint i;
	for (i = 0; i < SMTP_NUM_IDS; i++) {
		if (strncasecmp(smtp_cmds[i].cmd, line, strlen(smtp_cmds[i].cmd)) == 0) {
			return (smtp_cmd_id) i;
		}
	}
	return SMTP_ERROR;
}

static gboolean
get_size(gchar *line, unsigned long *msize) {
	gchar *s = NULL;

	/* hope we need not to handle cases like SiZe= ...*/
	s = strstr(line, "SIZE=");
	if (!s) {
		/* try it in lowercase too */
		if (!(s = strstr(line, "size="))) {
			return FALSE;
		}
	}
	s += 5;
	*msize = atol(s);
	DEBUG(5) debugf("get_size(): line=%s, msize=%ld\n", line, *msize);

	return TRUE;
}


/* this is a quick hack: we expect the address to be syntactically correct
   and containing the mailbox only, though we first check for size in
   smtp_in().
*/
static gboolean
get_address(gchar * line, gchar * addr)
{
	gchar *p = line;
	gchar *q = addr;

	/* skip MAIL FROM: and RCPT TO: */
	while (*p && (*p != ':')) {
		p++;
	}
	p++;

	/* skip spaces: */
	while (*p && isspace(*p)) {
		p++;
	}

	/* get address: */
	while (*p && !isspace(*p) && (q < addr + MAX_ADDRESS - 1)) {
		*(q++) = *(p++);
	}
	*q = 0;

	return TRUE;
}

static smtp_connection*
create_base(gchar * remote_host)
{
	smtp_connection *base = g_malloc(sizeof(smtp_connection));
	if (!base) {
		return NULL;
	}

	base->remote_host = g_strdup(remote_host);

	base->prot = PROT_SMTP;
	base->next_id = 0;
	base->helo_seen = 0;
	base->from_seen = 0;
	base->rcpt_seen = 0;
	base->msg = NULL;

	return base;
}

static void
smtp_printf(FILE * out, gchar * fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	DEBUG(4) {
		gchar buf[256];
		va_list args_copy;

		va_copy(args_copy, args);
		vsnprintf(buf, 255, fmt, args_copy);
		va_end(args_copy);

		debugf(">>>%s", buf);
	}

	vfprintf(out, fmt, args);
	fflush(out);

	va_end(args);
}

void
smtp_in(FILE * in, FILE * out, gchar * remote_host, gchar * ident)
{
	gchar *buffer;
	smtp_cmd_id cmd_id;
	message *msg = NULL;
	smtp_connection *psc;
	int len;
	unsigned long size, msize;

	DEBUG(5) debugf("smtp_in entered, remote_host = %s\n", remote_host);

	psc = create_base(remote_host);
	psc->msg = msg;

	buffer = (gchar *) g_malloc(BUF_LEN);
	if (!buffer) {
		/* this check is actually unneccessary as g_malloc()
		   aborts on failure */
		return;
	}

	/* send greeting string, containing ESMTP: */
	smtp_printf(out, "220 %s MasqMail %s ESMTP\r\n", conf.host_name, VERSION);

	while ((len = read_sockline(in, buffer, BUF_LEN, 5 * 60, READSOCKL_CHUG)) >= 0) {
		cmd_id = get_id(buffer);

		if (conf.defer_all) {
			/* I need this to debug delivery failures */
			smtp_printf(out, "421 %s service temporarily unavailable.\r\n", conf.host_name);
			destroy_message(msg);
			msg = NULL;
			return;
		}

		switch (cmd_id) {
		case SMTP_HELO:
			psc->prot = PROT_SMTP;
			psc->helo_seen = TRUE;
			smtp_printf(out, "250 %s pretty old mailer, huh?\r\n", conf.host_name);
			break;

		case SMTP_EHLO:
			psc->prot = PROT_ESMTP;
			psc->helo_seen = TRUE;
			smtp_printf(out, "250-%s Nice to meet you with ESMTP\r\n", conf.host_name);
			smtp_printf(out, "250-SIZE %d\r\n", conf.max_msg_size);
			smtp_printf(out, "250-PIPELINING\r\n");
			smtp_printf(out, "250 HELP\r\n");
			break;

		case SMTP_MAIL_FROM:
			{
				gchar buf[MAX_ADDRESS];
				address *addr;
	
				if (!psc->helo_seen) {
					smtp_printf(out, "503 need HELO or EHLO\r\n");
					break;
				}
				if (psc->from_seen) {
					smtp_printf(out, "503 MAIL FROM: already given.\r\n");
					break;
				}

				if (get_size(buffer, &msize)) {
					DEBUG(5) debugf("smtp_in(): get_size: msize=%ld, conf.mms=%d\n",
							msize, conf.max_msg_size);
					if (conf.max_msg_size && (msize > conf.max_msg_size)) {
						smtp_printf(out, "552 Message size exceeds fixed limit.\r\n");
						break;
					}
				}

				msg = create_message();
				msg->received_host = remote_host ? g_strdup(remote_host) : NULL;
				msg->received_prot = psc->prot;
				msg->ident = ident ? g_strdup(ident) : NULL;
				/* get transfer id and increment for next one */
				msg->transfer_id = (psc->next_id)++;
	
				get_address(buffer, buf);
				if (remote_host) {
					addr = create_address(buf, TRUE);
				} else {
					addr = create_address_qualified(buf, TRUE, conf.host_name);
				}
				if (!addr) {
					smtp_printf(out, "501 %s: syntax error.\r\n", buf);
				} else if (!addr->domain) {
					smtp_printf(out, "501 return path must be qualified.\r\n", buf);
				} else {
					psc->from_seen = TRUE;
					msg->return_path = addr;
					smtp_printf(out, "250 OK %s is a nice guy.\r\n", addr->address);
				}
			}
			break;

		case SMTP_RCPT_TO:
			{
				char buf[MAX_ADDRESS];
				address *addr;
	
				if (!psc->helo_seen) {
					smtp_printf(out, "503 need HELO or EHLO.\r\n");
					break;
				}
				if (!psc->from_seen) {
					smtp_printf(out, "503 need MAIL FROM: before RCPT TO:\r\n");
					break;
				}
	
				get_address(buffer, buf);
				if (remote_host) {
					addr = create_address(buf, TRUE);
				} else {
					addr = create_address_qualified(buf, TRUE, conf.host_name);
				}
				if (!addr) {
					smtp_printf(out, "501 %s: syntax error in address.\r\n", buf);
					break;
				}
				if (addr->local_part[0] == '|') {
					smtp_printf(out, "501 %s: no pipe allowed for SMTP connections\r\n", buf);
					break;
				}
				if (!addr->domain) {
					smtp_printf(out, "501 recipient address must be qualified.\r\n", buf);
					break;
				}
				gboolean do_relay = conf.do_relay;
				if (!do_relay) {
					do_relay = addr_is_local(msg->return_path);
					if (!do_relay) {
						do_relay = addr_is_local(addr);
					}
				}
				if (!do_relay) {
					smtp_printf(out, "550 relaying to %s denied.\r\n", addr_string(addr));
					break;
				}
				psc->rcpt_seen = TRUE;
				msg->rcpt_list = g_list_append(msg->rcpt_list, addr);
				smtp_printf(out, "250 OK %s is our friend.\r\n", addr->address);
			}
			break;

		case SMTP_DATA:
			if (!psc->helo_seen) {
				smtp_printf(out, "503 need HELO or EHLO.\r\n");
				break;
			}
			if (!psc->rcpt_seen) {
				smtp_printf(out, "503 need RCPT TO: before DATA\r\n");
				break;
			}
			accept_error err;

			smtp_printf(out, "354 okay, and do not forget the dot\r\n");

			err = accept_message(in, msg, conf.do_save_envelope_to ? ACC_SAVE_ENVELOPE_TO : 0);
			if (err != AERR_OK) {
				switch (err) {
				case AERR_TIMEOUT:
				case AERR_EOF:
					return;
				case AERR_SIZE:
					smtp_printf(out, "552 Error: message too large.\r\n");
					return;
				default:
					/* should never happen: */
					smtp_printf(out, "451 Unknown error\r\n");
					return;
				}
			}


			if (!spool_write(msg, TRUE)) {
				smtp_printf(out, "451 Could not write spool file\r\n");
				return;
			}
			pid_t pid;
			smtp_printf(out, "250 OK id=%s\r\n", msg->uid);

			if (remote_host != NULL) {
				logwrite(LOG_NOTICE, "%s <= <%s@%s> host=%s with %s\n", msg->uid,
				         msg->return_path->local_part, msg->return_path->domain,
				         remote_host, prot_names[psc->prot]);
			} else {
				logwrite(LOG_NOTICE, "%s <= <%s@%s> with %s\n", msg->uid,
				         msg->return_path->local_part, msg->return_path->domain,
				         prot_names[psc->prot]);
			}

			if (conf.do_queue) {
				DEBUG(1) debugf("queuing forced by configuration or option.\n");
			} else {
				pid = fork();
				if (pid == 0) {
					_exit(deliver(msg));
				} else if (pid < 0) {
					logwrite(LOG_ALERT, "could not fork for delivery, id = %s", msg->uid);
				}
			}
			psc->rcpt_seen = psc->from_seen = FALSE;
			destroy_message(msg);
			msg = NULL;
			break;

		case SMTP_QUIT:
			smtp_printf(out, "221 goodbye\r\n");
			destroy_message(msg);
			msg = NULL;
			return;

		case SMTP_RSET:
			psc->from_seen = psc->rcpt_seen = FALSE;
			destroy_message(msg);
			msg = NULL;
			smtp_printf(out, "250 OK\r\n");
			break;

		case SMTP_NOOP:
			smtp_printf(out, "250 OK\r\n");
			break;

		case SMTP_HELP:
			{
				int i;

				smtp_printf(out, "214-supported commands:\r\n");
				for (i = 0; i < SMTP_NUM_IDS - 1; i++) {
					smtp_printf(out, "214-%s\r\n", smtp_cmds[i].cmd);
				}
				smtp_printf(out, "214 %s\r\n", smtp_cmds[i].cmd);
			}
			break;

		default:
			smtp_printf(out, "501 command not recognized\r\n");
			DEBUG(1) debugf("command not recognized, was '%s'\n", buffer);
			break;
		}
	}
	switch (len) {
	case -3:
		logwrite(LOG_NOTICE, "connection timed out\n");
		break;
	case -2:
		logwrite(LOG_NOTICE, "line overflow\n");
		break;
	case -1:
		logwrite(LOG_NOTICE, "received EOF\n");
		break;
	default:
		break;
	}
}
#endif
