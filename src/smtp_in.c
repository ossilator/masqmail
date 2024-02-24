// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "readsock.h"

/*
**  I always forget these rfc numbers:
**  RFC 821  (SMTP)
**  RFC 1869 (ESMTP)
**  RFC 1870 (ESMTP SIZE)
**  RFC 2197 (ESMTP PIPELINE)
**  RFC 2554 (ESMTP AUTH)
*/


// keep in sync with smtp_cmd_id!
static const char * const smtp_cmds[] = {
	"HELO",
	"EHLO",
	"MAIL FROM:",
	"RCPT TO:",
	"DATA",
	"QUIT",
	"RSET",
	"NOOP",
	"HELP"
};

static smtp_cmd_id
get_id(const gchar *line)
{
	gint i;
	for (i = 0; i < SMTP_NUM_IDS; i++) {
		if (strncasecmp(smtp_cmds[i], line, strlen(smtp_cmds[i])) == 0) {
			return (smtp_cmd_id) i;
		}
	}
	return SMTP_ERROR;
}

static gboolean
get_size(gchar *line, gssize *msize)
{
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
	DEBUG(5) debugf("get_size(): line=%s, msize=%" G_GSSIZE_FORMAT "\n",
	                line, *msize);

	return TRUE;
}


/*
**  this is a quick hack: we expect the address to be syntactically correct
**  and containing the mailbox only, though we first check for size in
**  smtp_in().
**  Return false if address is too long.
*/
static gboolean
get_address(gchar *line, gchar *addr)
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
	while (*p && !isspace(*p)) {
		if (q >= addr + MAX_ADDRESS-1) {
			*q = '\0';
			return FALSE;
		}
		*(q++) = *(p++);
	}
	*q = '\0';

	return TRUE;
}

static void
init_base(smtp_connection *base)
{
	base->prot = PROT_SMTP;
	base->next_id = 0;
	base->helo_seen = 0;
	base->from_seen = 0;
	base->rcpt_seen = 0;
}

static void G_GNUC_PRINTF(2, 3)
smtp_printf(FILE *out, gchar *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	DEBUG(4) {
		gchar buf[256];
		va_list args_copy;

		va_copy(args_copy, args);
		vsnprintf(buf, 255, fmt, args_copy);
		va_end(args_copy);

		debugf(">>>%s\n", buf);
	}

	vfprintf(out, fmt, args);
	fflush(out);

	va_end(args);
}

void
smtp_in(FILE *in, FILE *out, gchar *remote_host)
{
	smtp_cmd_id cmd_id;
	message *msg = NULL;
	int len;
	gssize msize;
	smtp_connection psc[1];
	gchar buffer[BUF_LEN];

	DEBUG(5) debugf("smtp_in entered, remote_host = %s\n", remote_host);

	init_base(psc);

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
			smtp_printf(out, "250-SIZE %" G_GSSIZE_FORMAT "\r\n", conf.max_msg_size);
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
					DEBUG(5) debugf("smtp_in(): get_size: msize=%" G_GSSIZE_FORMAT
					                ", conf.mms=%" G_GSSIZE_FORMAT "\n",
							msize, conf.max_msg_size);
					if (conf.max_msg_size && (msize > conf.max_msg_size)) {
						smtp_printf(out, "552 Message size exceeds fixed limit.\r\n");
						break;
					}
				}
				if (!get_address(buffer, buf)) {
					smtp_printf(out, "553 Address too long.\r\n");
					break;
				}

				msg = create_message();
				msg->received_host = remote_host;
				msg->received_prot = psc->prot;
				/* get transfer id and increment for next one */
				msg->transfer_id = (psc->next_id)++;
	
				addr = create_address(buf, A_RFC821, remote_host ? NULL : conf.host_name);
				if (!addr) {
					smtp_printf(out, "501 %s: syntax error.\r\n", buf);
				} else if (!addr->domain) {
					smtp_printf(out, "501 return path must be qualified.\r\n");
					destroy_address(addr);
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
				if (!get_address(buffer, buf)) {
					smtp_printf(out, "553 Address too long.\r\n");
					break;
				}
	
				addr = create_address(buf, A_RFC821, remote_host ? NULL : conf.host_name);
				if (!addr) {
					smtp_printf(out, "501 %s: syntax error in address.\r\n", buf);
					break;
				}
				if (!addr->domain) {
					/* TODO: ``postmaster'' may be unqualified */
					smtp_printf(out, "501 recipient address must be qualified.\r\n");
					destroy_address(addr);
					break;
				}
				if (!(conf.do_relay || addr_is_local(msg->return_path) || addr_is_local(addr))) {
					smtp_printf(out, "550 relaying to %s denied.\r\n", addr_string(addr));
					destroy_address(addr);
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
			smtp_printf(out, "250 OK id=%s\r\n", msg->uid);

			if (remote_host != NULL) {
				logwrite(LOG_INFO, "%s <= <%s@%s> host=%s with %s\n", msg->uid,
				         msg->return_path->local_part, msg->return_path->domain,
				         remote_host, prot_names[psc->prot]);
			} else {
				logwrite(LOG_INFO, "%s <= <%s@%s> with %s\n", msg->uid,
				         msg->return_path->local_part, msg->return_path->domain,
				         prot_names[psc->prot]);
			}

			deliver(msg);

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
					smtp_printf(out, "214-%s\r\n", smtp_cmds[i]);
				}
				smtp_printf(out, "214 %s\r\n", smtp_cmds[i]);
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
