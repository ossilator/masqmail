/*
**  MasqMail
**  Copyright (C) 1999-2001 Oliver Kurth
**  Copyright (C) 2010 markus schnalke <meillo@marmaro.de>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "masqmail.h"
#include "readsock.h"

/* must match PROT_* in masqmail.h */
gchar *prot_names[] = {
	"local",
	"SMTP",
	"ESMTP",
	"(unknown)"  /* should not happen, but better than crashing. */
};

static gchar*
string_base62(gchar *res, guint value, gchar len)
{
	static gchar base62_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
	gchar *p = res + len;
	*p = '\0';
	while (p > res) {
		*(--p) = base62_chars[value % 62];
		value /= 62;
	}
	return res;
}

/*
**  accept message from anywhere.
**  A message from local is indicated by msg->recieved_host == NULL
**
**  The -t option: With the ACC_RCPT_FROM_HEAD flag the addrs found found
**  in To/Cc/Bcc headers are added to the recipient list.
*/
accept_error
accept_message_stream(FILE *in, message *msg, guint flags)
{
	gchar *line, *line1;
	int line_size = MAX_DATALINE;
	gboolean in_headers = TRUE;
	header *hdr = NULL;
	gint line_cnt = 0, data_size = 0;

	line = g_malloc(line_size);
	*line = '\0';

	while (1) {
		int len = read_sockline1(in, &line, &line_size, 5 * 60,
				READSOCKL_CVT_CRLF);
		line1 = line;

		if ((*line == '.') && (!(flags & ACC_DOT_IGNORE))) {
			if (line[1] == '\n') {
				g_free(line);
				break;
			}
			line1++;
		}

		if (len==-1 && (flags & (ACC_DOT_IGNORE | ACC_NODOT_RELAX))) {
			/* at EOF but last line was not terminated by CR */
			/* some MUAs allow unterminated lines */
			gint len1 = strlen(line1);
			if (len1 > 0 && line1[len1-1] != '\n') {
				line1[len1] = '\n';
				line1[len1+1] = '\0';
				msg->data_list = g_list_prepend(msg->data_list,
						g_strdup(line1));
				data_size += strlen(line1);
				line_cnt++;
			}
			break;

		} else if (len == -1) {
			g_free(line);
			return AERR_EOF;

		} else if (len == -2) {
			/* should not happen any more */
			g_free(line);
			return AERR_OVERFLOW;

		} else if (len == -3) {
			g_free(line);
			return AERR_TIMEOUT;

		} else if (len <= 0) {
			/* does not happen */
			g_free(line);
			DEBUG(5) debugf("read_sockline returned %d\n", len);
			return AERR_UNKNOWN;

		}

		if (in_headers) {
			/* some pop servers send the 'From ' line, skip it: */
			if (!msg->hdr_list && strncmp(line1, "From ", 5)==0) {
				continue;
			}

			if (*line1 == ' ' || *line1 == '\t') {
				/* continuation of 'folded' header: */
				if (hdr) {
					char *cp;
					cp = g_strconcat(hdr->header, line1,
							NULL);
					hdr->value = cp + (hdr->value -
							hdr->header);
					free(hdr->header);
					hdr->header = cp;
				}
			} else if (*line1 == '\n') {
				/* an empty line marks end of headers */
				in_headers = FALSE;

			} else if ((hdr = get_header(line1))) {
				/* another header */
				msg->hdr_list = g_list_append(msg->hdr_list, hdr);
			} else {
				/*
				**  Should be another header but none was
				**  recognized, so this seems to be the first
				**  data line of a broken mailer which does
				**  not add an empty line after the headers.
				*/
				in_headers = FALSE;
				msg->data_list = g_list_prepend(msg->data_list,
						g_strdup(line1));
			}
		} else {
			/* message body */
			msg->data_list = g_list_prepend(msg->data_list,
					g_strdup(line1));
			data_size += strlen(line1);
			line_cnt++;
		}

		if (conf.max_msg_size && (data_size > conf.max_msg_size)) {
			DEBUG(4) debugf("accept_message_stream(): "
					"received %d bytes (conf.max_msg_size=%d)\n",
			                data_size, conf.max_msg_size);
			return AERR_SIZE;
		}
	}
	DEBUG(4) debugf("received %d lines of data (%d bytes)\n",
			line_cnt, data_size);

	if (!msg->data_list) {
		/* make sure data list is not NULL */
		msg->data_list = g_list_append(NULL, g_strdup(""));
	}
	msg->data_list = g_list_reverse(msg->data_list);

	/* we have succesfully received the mail data */

	msg->data_size = data_size;
	msg->received_time = time(NULL);

	return AERR_OK;
}

static void
ensure_return_path(message *msg)
{
	GList *hdr_list;
	header *hdr;
	gchar *addr;

	if (msg->return_path) {
		return;
	}

	DEBUG(3) debugf("return_path == NULL\n");

	hdr_list = find_header(msg->hdr_list, HEAD_SENDER, NULL);
	if (!hdr_list) {
		hdr_list = find_header(msg->hdr_list, HEAD_FROM, NULL);
	}
	if (hdr_list) {
		hdr = (header *) (g_list_first(hdr_list)->data);

		DEBUG(5) debugf("hdr->value = '%s'\n", hdr->value);

		addr = g_strstrip(g_strdup(hdr->value));
		msg->return_path = create_address_qualified(addr,
				FALSE, msg->received_host);
		if (msg->return_path) {
			DEBUG(3) debugf("setting return_path to %s\n",
					addr_string(msg->return_path));
			msg->hdr_list = g_list_append(msg->hdr_list,
					create_header(HEAD_UNKNOWN,
					"X-Warning: return path set from %s "
					"address\n",
					(hdr->id == HEAD_SENDER) ?
					"Sender:" : "From:"));
		}
		g_free(addr);
	}
	if (!msg->return_path) {
		/* no Sender: or From: or create_address_qualified failed */
		msg->return_path = create_address_qualified("postmaster",
				TRUE, conf.host_name);
		DEBUG(3) debugf("setting return_path to %s\n",
				addr_string(msg->return_path));
		msg->hdr_list = g_list_append(msg->hdr_list,
				create_header(HEAD_UNKNOWN,
				"X-Warning: real return path is unknown\n"));
	}
}

static accept_error
scan_headers(message *msg, guint flags)
{
	gboolean has_id = FALSE;
	gboolean has_date = FALSE;
	gboolean has_sender = FALSE;
	gboolean has_from = FALSE;
	gboolean has_to_or_cc = FALSE;
	GList *hdr_node, *hdr_node_next;
	header *hdr;

	for (hdr_node = g_list_first(msg->hdr_list); hdr_node;
			hdr_node = hdr_node_next) {
		hdr_node_next = g_list_next(hdr_node);
		hdr = ((header *) (hdr_node->data));
		DEBUG(5) debugf("scanning headers: %s", hdr->header);
		switch (hdr->id) {
		case HEAD_MESSAGE_ID:
			has_id = TRUE;
			break;
		case HEAD_DATE:
			has_date = TRUE;
			break;
		case HEAD_FROM:
			has_from = TRUE;
			break;
		case HEAD_SENDER:
			has_sender = TRUE;
			break;
		case HEAD_TO:
		case HEAD_CC:
			has_to_or_cc = TRUE;
			/* fall through */
		case HEAD_BCC:
			if (flags & ACC_RCPT_FROM_HEAD) {
				/* -t option (see comment above) */
				DEBUG(5) debugf("hdr->value = %s\n",
						hdr->value);
				if (hdr->value) {
					msg->rcpt_list = addr_list_append_rfc822(msg->rcpt_list, hdr->value, conf.host_name);
				}
			}
			if (hdr->id == HEAD_BCC) {
				DEBUG(3) debugf("removing 'Bcc' header\n");
				msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
				g_list_free_1(hdr_node);
				destroy_header(hdr);
			}
			break;
		case HEAD_ENVELOPE_TO:
			if (flags & ACC_SAVE_ENVELOPE_TO) {
				DEBUG(3) debugf("creating 'X-Orig-Envelope-To' header\n");
				msg->hdr_list = g_list_prepend(msg->hdr_list,
						create_header(HEAD_UNKNOWN,
						"X-Orig-Envelope-To: %s",
						hdr->value));
			}
			DEBUG(3) debugf("removing 'Envelope-To' header\n");
			msg->hdr_list = g_list_remove_link(msg->hdr_list,
					hdr_node);
			g_list_free_1(hdr_node);
			destroy_header(hdr);
			break;
		case HEAD_RETURN_PATH:
			if (flags & ACC_MAIL_FROM_HEAD) {
				/* usually POP3 accept */
				msg->return_path = create_address_qualified(hdr->value, TRUE, msg->received_host);
				DEBUG(3) debugf("setting return_path to %s\n",
						addr_string(msg->return_path));
			}
			DEBUG(3) debugf("removing 'Return-Path' header\n");
			msg->hdr_list = g_list_remove_link(msg->hdr_list,
					hdr_node);
			g_list_free_1(hdr_node);
			destroy_header(hdr);
			break;
		default:
			break;  /* make compiler happy */
		}
	}

	/*
	**  TODO: do we still need this as we don't fetch
	**        mail anymore?
	**  This can happen for pop3 accept only and if no
	**  Return-Path: header was given
	*/
	ensure_return_path(msg);

	/* here we should have our recipients, fail if not: */
	if (!msg->rcpt_list) {
		logwrite(LOG_WARNING, "no recipients found in message\n");
		return AERR_NORCPT;
	}

	if (!has_sender && !has_from) {
		DEBUG(3) debugf("adding 'From:' header\n");
		if (msg->full_sender_name) {
			msg->hdr_list = g_list_append(msg->hdr_list,
					create_header(HEAD_FROM,
					"From: \"%s\" <%s@%s>\n",
					msg->full_sender_name,
					msg->return_path->local_part,
					msg->return_path->domain));
		} else {
			msg->hdr_list = g_list_append(msg->hdr_list,
					create_header(HEAD_FROM,
					"From: <%s@%s>\n",
					msg->return_path->local_part,
					msg->return_path->domain));
		}
	}
	if (!has_to_or_cc) {
		DEBUG(3) debugf("no To: or Cc: header, hence adding "
				"`To: undisclosed recipients:;'\n");
		msg->hdr_list = g_list_append(msg->hdr_list,
				create_header(HEAD_TO,
				"To: undisclosed-recipients:;\n"));
	}
	if (!has_date) {
		DEBUG(3) debugf("adding 'Date:' header\n");
		msg->hdr_list = g_list_append(msg->hdr_list,
				create_header(HEAD_DATE, "Date: %s\n",
				rec_timestamp()));
	}
	if (!has_id) {
		DEBUG(3) debugf("adding 'Message-ID:' header\n");
		msg->hdr_list = g_list_append(msg->hdr_list,
				create_header(HEAD_MESSAGE_ID,
				"Message-ID: <%s@%s>\n",
				msg->uid, conf.host_name));
	}

	return AERR_OK;
}

static void
add_received_hdr(message *msg)
{
	gchar *for_string = NULL;
	header *hdr = NULL;
	address *addr;

	DEBUG(3) debugf("adding 'Received:' header\n");
	if (g_list_length(msg->rcpt_list) == 1) {
		/* The `for' part only if exactly one rcpt is present */
		addr = (address *) (g_list_first(msg->rcpt_list)->data);
		for_string = g_strdup_printf("\n\tfor %s", addr_string(addr));
	}
	if (!msg->received_host) {
		/* received locally */
		hdr = create_header(HEAD_RECEIVED,
				"Received: by %s (%s %s, from userid %d)\n"
				"\tid %s%s; %s\n",
				conf.host_name, PACKAGE, VERSION, geteuid(),
				msg->uid,
				for_string ? for_string : "", rec_timestamp());
	} else {
		/* received from remote */
		DEBUG(5) debugf("adding 'Received:' header (5)\n");
		hdr = create_header(HEAD_RECEIVED,
				"Received: from %s\n"
				"\tby %s with %s (%s %s)\n"
				"\tid %s%s; %s\n",
				msg->received_host, conf.host_name,
				prot_names[msg->received_prot], PACKAGE,
				VERSION, msg->uid,
				for_string ? for_string : "", rec_timestamp());
	}
	msg->hdr_list = g_list_prepend(msg->hdr_list, hdr);
	if (for_string) {
		g_free(for_string);
	}
}

accept_error
accept_message_prepare(message *msg, guint flags)
{
	DEBUG(5) debugf("accept_message_prepare()\n");

	/* generate unique message id */
	msg->uid = g_malloc(14);
	string_base62(msg->uid, time(NULL), 6);
	msg->uid[6] = '-';
	string_base62(msg->uid + 7, getpid(), 3);
	msg->uid[10] = '-';
	string_base62(msg->uid + 11, msg->transfer_id, 2);
	msg->uid[13] = '\0';

	/* if local, get password entry and set return path if missing */
	if (!msg->received_host) {
		struct passwd *passwd = NULL;

		passwd = g_memdup(getpwuid(geteuid()), sizeof(struct passwd));
		msg->ident = g_strdup(passwd->pw_name);
		if (!msg->return_path) {
			gchar *path = g_strdup_printf("<%s@%s>",
					passwd->pw_name, conf.host_name);
			DEBUG(3) debugf("setting return_path for local "
					"accept: %s\n", path);
			msg->return_path = create_address(path, TRUE);
			g_free(path);
		}
	}

	if (scan_headers(msg, flags) == AERR_NORCPT) {
		return AERR_NORCPT;
	}

	/* after the hdrs are scanned because we need to know the rcpts */
	add_received_hdr(msg);

	return AERR_OK;
}

accept_error
accept_message(FILE *in, message *msg, guint flags)
{
	accept_error err;

	err = accept_message_stream(in, msg, flags);
	if (err == AERR_OK) {
		err = accept_message_prepare(msg, flags);
	}

	return err;
}
