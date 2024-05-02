// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "readsock.h"

#include <pwd.h>

/* must match PROT_* in masqmail.h */
const gchar * const prot_names[] = {
	"local",
	"SMTP",
	"ESMTP",
	"(unknown)"  /* should not happen, but better than crashing. */
};

static gchar*
string_base62(gchar *res, guint value, gchar len)
{
	static const gchar base62_chars[] =
			"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
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
static accept_error
accept_message_stream(FILE *in, message *msg, guint flags)
{
	gchar *line, *line1;
	int line_size = MAX_DATALINE;
	gboolean in_headers = TRUE;
	header *hdr = NULL;
	gssize data_size = 0;
	gint line_cnt = 0;

	line = g_malloc(line_size);
	*line = '\0';

	while (1) {
		int len = read_sockline1(in, &line, &line_size, 5 * 60,
				READSOCKL_CVT_CRLF);
		line1 = line;

		if ((*line == '.') && (!(flags & ACC_DOT_IGNORE))) {
			if (line[1] == '\n') {
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
			g_free(line);
			DEBUG(4) debugf("accept_message_stream(): received %" G_GSSIZE_FORMAT
			                " bytes (conf.max_msg_size=%" G_GSSIZE_FORMAT ")\n",
			                data_size, conf.max_msg_size);
			return AERR_SIZE;
		}
	}
	g_free(line);
	DEBUG(4) debugf("received %d lines of data (%" G_GSSIZE_FORMAT " bytes)\n",
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

static accept_error
scan_headers(message *msg, guint flags)
{
	gboolean has_id = FALSE;
	gboolean has_date = FALSE;
	gboolean has_sender = FALSE;
	gboolean has_from = FALSE;
	gboolean has_to_or_cc = FALSE;

	foreach_mut (header *hdr, hdr_node, msg->hdr_list) {
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
			G_GNUC_FALLTHROUGH;
		case HEAD_BCC:
			if (flags & ACC_RCPT_FROM_HEAD) {
				/* -t option (see comment above) */
				DEBUG(5) debugf("hdr->value = %s\n",
						hdr->value);
				if (*hdr->value) {
					msg->rcpt_list = addr_list_append_rfc822(msg->rcpt_list, hdr->value, conf.host_name);
				}
			}
			if (hdr->id == HEAD_BCC) {
				DEBUG(3) debugf("removing 'Bcc' header\n");
				msg->hdr_list = g_list_delete_link(msg->hdr_list, hdr_node);
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
			msg->hdr_list = g_list_delete_link(msg->hdr_list, hdr_node);
			destroy_header(hdr);
			break;
		case HEAD_RETURN_PATH:
			DEBUG(3) debugf("removing 'Return-Path' header\n");
			msg->hdr_list = g_list_delete_link(msg->hdr_list, hdr_node);
			destroy_header(hdr);
			break;
		default:
			break;  /* make compiler happy */
		}
	}

	/* here we should have our recipients, fail if not: */
	if (!msg->rcpt_list) {
		logwrite(LOG_WARNING, "no recipients found in message\n");
		return AERR_NORCPT;
	}

	if (!has_sender && !has_from) {
		DEBUG(3) debugf("adding 'From:' header\n");
		if (msg->full_sender_name) {
			msg->hdr_list = g_list_append(msg->hdr_list,
					create_header(HEAD_FROM, "From: \"%s\" <%s>\n",
							msg->full_sender_name, msg->return_path->address));
		} else {
			msg->hdr_list = g_list_append(msg->hdr_list,
					create_header(HEAD_FROM, "From: %s\n",
							msg->return_path->address));
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

	DEBUG(3) debugf("adding 'Received:' header\n");
	if (g_list_length(msg->rcpt_list) == 1) {
		/* The `for' part only if exactly one rcpt is present */
		const recipient *addr = msg->rcpt_list->data;
		for_string = g_strdup_printf("\n\tfor <%s>", addr->address->address);
	}
	if (!msg->received_host) {
		/* received locally */
		hdr = create_header(HEAD_RECEIVED,
				"Received: by %s (%s %s, from userid %u)\n"
				"\tid %s%s; %s\n",
				conf.host_name, PACKAGE, VERSION, conf.orig_uid,
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
	g_free(for_string);
}

static accept_error
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
		struct passwd *passwd = getpwuid(conf.orig_uid);
		msg->ident = g_strdup(passwd->pw_name);
		if (!msg->return_path) {
			msg->return_path = create_address_raw(msg->ident, conf.host_name);
			DEBUG(3) debugf("setting return_path for local accept: %s\n",
			                msg->return_path->address);
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
