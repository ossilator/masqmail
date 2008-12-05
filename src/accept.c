/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth

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

gchar *prot_names[] = {
	"local",
	"bsmtp",
	"smtp",
	"esmtp",
	"pop3",
	"apop",
	"(unknown)"  /* should not happen, but better than crashing. */
};

static gchar*
string_base62(gchar * res, guint value, gchar len)
{
	static gchar base62_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	gchar *p = res + len;
	*p = '\0';
	while (p > res) {
		*(--p) = base62_chars[value % 62];
		value /= 62;
	}
	return res;
}

static gint
_g_list_addr_isequal(gconstpointer a, gconstpointer b)
{
	address *addr1 = (address *) a;
	address *addr2 = (address *) b;
	int ret;

	if ((ret = strcasecmp(addr1->domain, addr2->domain)) == 0)
		return strcmp(addr1->local_part, addr2->local_part);
	else
		return ret;
}

/* accept message from anywhere.
   A locally originating message is indicated by msg->recieved_host == NULL

   If the flags ACC_DEL_RCPTS is set, recipients in the msg->rcpt_list is
   copied and items occuring in it will be removed from the newly constructed
   (from To/Cc/Bcc headers if ACC_RCPT_TO is set) rcpt_list.
*/

accept_error
accept_message_stream(FILE * in, message * msg, guint flags)
{
	gchar *line, *line1;
	int line_size = MAX_DATALINE;
	gboolean in_headers = TRUE;
	header *hdr = NULL;
	gint line_cnt = 0, data_size = 0;

	line = g_malloc(line_size);
	line[0] = '\0';

	while (TRUE) {
		int len = read_sockline1(in, &line, &line_size, 5 * 60, READSOCKL_CVT_CRLF);

		line1 = line;

		if ((line[0] == '.') && (!(flags & ACC_NODOT_TERM))) {
			if (line[1] == '\n') {
				g_free(line);
				break;
			}
			line1++;
		}

		if (len <= 0) {
			if ((len == -1) && ((flags & ACC_NODOT_TERM) || (flags & ACC_NODOT_RELAX))) {
				/* we got an EOF, and the last line was not terminated by a CR */
				gint len1 = strlen(line1);
				if (len1 > 0) {  /* == 0 is 'normal' (EOF after a CR) */
					if (line1[len1 - 1] != '\n') {  /* some mail clients allow unterminated lines */
						line1[len1] = '\n';
						line1[len1 + 1] = '\0';
						msg->data_list = g_list_prepend(msg->data_list, g_strdup(line1));
						data_size += strlen(line1);
						line_cnt++;
					}
				}
				break;
			} else {
				g_free(line);
				if (len == -1) {
					return AERR_EOF;
				} else if (len == -2) {
					/* should not happen any more */
					return AERR_OVERFLOW;
				} else if (len == -3) {
					return AERR_TIMEOUT;
				} else {
					/* does not happen */
					DEBUG(5) debugf("read_sockline returned %d\n", len);
					return AERR_UNKNOWN;
				}
			}
		} else {
			if (in_headers) {

				/* some pop servers send the 'From ' line, skip it: */
				if (msg->hdr_list == NULL)
					if (strncmp(line1, "From ", 5) == 0)
						continue;

				if (line1[0] == ' ' || line1[0] == '\t') {
					/* continuation of 'folded' header: */
					if (hdr) {
						hdr->header = g_strconcat(hdr->header, line1, NULL);
					}

				} else if (line1[0] == '\n') {
					/* an empty line marks end of headers */
					in_headers = FALSE;
				} else {
					/* in all other cases we expect another header */
					if ((hdr = get_header(line1)))
						msg->hdr_list = g_list_append(msg->hdr_list, hdr);
					else {
						/* if get_header() returns NULL, no header was recognized,
						   so this seems to be the first data line of a broken mailer
						   which does not send an empty line after the headers */
						in_headers = FALSE;
						msg->data_list = g_list_prepend(msg->data_list, g_strdup(line1));
					}
				}
			} else {
				msg->data_list = g_list_prepend(msg->data_list, g_strdup(line1));
				data_size += strlen(line1);
				line_cnt++;
			}
		}
	}

	if (msg->data_list != NULL)
		msg->data_list = g_list_reverse(msg->data_list);
	else
		/* make sure data list is not NULL: */
		msg->data_list = g_list_append(NULL, g_strdup(""));

	DEBUG(4) debugf("received %d lines of data (%d bytes)\n", line_cnt, data_size);
	/* we get here after we succesfully received the mail data */

	msg->data_size = data_size;
	msg->received_time = time(NULL);

	return AERR_OK;
}

accept_error
accept_message_prepare(message * msg, guint flags)
{
	struct passwd *passwd = NULL;
	GList *non_rcpt_list = NULL;
	time_t rec_time = time(NULL);

	DEBUG(5) debugf("accept_message_prepare()\n");

	/* create unique message id */
	msg->uid = g_malloc(14);

	string_base62(msg->uid, rec_time, 6);
	msg->uid[6] = '-';
	string_base62(&(msg->uid[7]), getpid(), 3);
	msg->uid[10] = '-';
	string_base62(&(msg->uid[11]), msg->transfer_id, 2);
	msg->uid[13] = 0;

	/* if local, get password entry */
	if (msg->received_host == NULL) {
		passwd = g_memdup(getpwuid(geteuid()), sizeof(struct passwd));
		msg->ident = g_strdup(passwd->pw_name);
	}

	/* set return path if local */
	if (msg->return_path == NULL && msg->received_host == NULL) {
		gchar *path = g_strdup_printf("<%s@%s>", passwd->pw_name, conf.host_name);
		DEBUG(3) debugf("setting return_path for local accept: %s\n", path);
		msg->return_path = create_address(path, TRUE);
		g_free(path);
	}

	/* -t option */
	if (flags & ACC_DEL_RCPTS) {
		non_rcpt_list = msg->rcpt_list;
		msg->rcpt_list = NULL;
	}

	/* scan headers */
	{
		gboolean has_id = FALSE;
		gboolean has_date = FALSE;
		gboolean has_sender = FALSE;
		gboolean has_from = FALSE;
		gboolean has_rcpt = FALSE;
		gboolean has_to_or_cc = FALSE;
		GList *hdr_node, *hdr_node_next;
		header *hdr;

		for (hdr_node = g_list_first(msg->hdr_list);
		     hdr_node != NULL; hdr_node = hdr_node_next) {
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
			case HEAD_BCC:
				has_rcpt = TRUE;
				if (flags & ACC_RCPT_FROM_HEAD) {
					DEBUG(5) debugf("hdr->value = %s\n", hdr->value);
					if (hdr->value) {
						msg->rcpt_list = addr_list_append_rfc822(msg->rcpt_list, hdr->value, conf.host_name);
					}
				}
				if ((flags & ACC_DEL_BCC) && (hdr->id == HEAD_BCC)) {
					DEBUG(3) debugf("removing 'Bcc' header\n");
					msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
					g_list_free_1(hdr_node);
					destroy_header(hdr);
				} else
					has_to_or_cc = TRUE;
				break;
			case HEAD_ENVELOPE_TO:
				if (flags & ACC_SAVE_ENVELOPE_TO) {
					DEBUG(3) debugf("creating 'X-Orig-Envelope-To' header\n");
					msg->hdr_list = g_list_prepend(msg->hdr_list, create_header(HEAD_UNKNOWN,
					                               "X-Orig-Envelope-to: %s", hdr->value));
				}
				DEBUG(3) debugf("removing 'Envelope-To' header\n");
				msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
				g_list_free_1(hdr_node);
				destroy_header(hdr);
				break;
			case HEAD_RETURN_PATH:
				if (flags & ACC_MAIL_FROM_HEAD) {
					/* usually POP3 accept */
					msg->return_path = create_address_qualified(hdr->value, TRUE, msg->received_host);
					DEBUG(3) debugf("setting return_path to %s\n", addr_string(msg->return_path));
				}
				DEBUG(3) debugf("removing 'Return-Path' header\n");
				msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
				g_list_free_1(hdr_node);
				destroy_header(hdr);
				break;
			default:
				break;  /* make compiler happy */
			}
		}

		if (msg->return_path == NULL) {
			/* this can happen for pop3 accept only and if no Return-path: header was given */
			GList *hdr_list;
			header *hdr;

			DEBUG(3) debugf("return_path == NULL\n");

			hdr_list = find_header(msg->hdr_list, HEAD_SENDER, NULL);
			if (!hdr_list)
				hdr_list = find_header(msg->hdr_list, HEAD_FROM, NULL);
			if (hdr_list) {
				gchar *addr;
				hdr = (header *) (g_list_first(hdr_list)->data);

				DEBUG(5) debugf("hdr->value = '%s'\n", hdr->value);

				addr = g_strdup(hdr->value);
				g_strchomp(addr);

				if ((msg->return_path = create_address_qualified(addr, FALSE, msg->received_host)) != NULL) {
					DEBUG(3) debugf("setting return_path to %s\n", addr_string(msg->return_path));
					msg->hdr_list = g_list_append(msg->hdr_list, create_header(HEAD_UNKNOWN,
					                              "X-Warning: return path set from %s address\n",
					                              hdr->id == HEAD_SENDER ? "Sender:" : "From:"));
				}
				g_free(addr);
			}
			if (msg->return_path == NULL) {  /* no Sender: or From: or create_address_qualified failed */
				msg->return_path = create_address_qualified("postmaster", TRUE, conf.host_name);
				DEBUG(3) debugf("setting return_path to %s\n", addr_string(msg->return_path));
				msg->hdr_list = g_list_append(msg->hdr_list, create_header(HEAD_UNKNOWN,
				                              "X-Warning: real return path is unkown\n"));
			}
		}

		if (flags & ACC_DEL_RCPTS) {
			GList *rcpt_node;
			foreach(non_rcpt_list, rcpt_node) {
				address *rcpt = (address *) (rcpt_node->data);
				GList *node;
				if ((node = g_list_find_custom(msg->rcpt_list, rcpt, _g_list_addr_isequal))) {
					DEBUG(3) debugf("removing rcpt address %s\n", addr_string(node->data));
					msg->rcpt_list = g_list_remove_link(msg->rcpt_list, node);
					destroy_address((address *) (node->data));
					g_list_free_1(node);
				}
			}
		}

		/* here we should have our recipients, fail if not: */
		if (msg->rcpt_list == NULL) {
			logwrite(LOG_WARNING, "no recipients found in message\n");
			return AERR_NORCPT;
		}

		if (!(has_sender || has_from)) {
			DEBUG(3) debugf("adding 'From' header\n");
			msg->hdr_list = g_list_append(msg->hdr_list,
			                msg->full_sender_name
			                ?
			                  create_header(HEAD_FROM, "From: \"%s\" <%s@%s>\n", msg->full_sender_name,
			                                msg->return_path->local_part, msg->return_path->domain)
			                :
			                  create_header(HEAD_FROM, "From: <%s@%s>\n",
			                                msg->return_path->local_part, msg->return_path->domain)
			                );
		}
		if ((flags & ACC_HEAD_FROM_RCPT) && !has_rcpt) {
			GList *node;
			DEBUG(3) debugf("adding 'To' header(s)\n");
			for (node = g_list_first(msg->rcpt_list); node; node = g_list_next(node)) {
				msg->hdr_list = g_list_append(msg->hdr_list,
				                              create_header(HEAD_TO, "To: %s\n", addr_string(msg-> return_path)));
			}
		}
		if ((flags & ACC_DEL_BCC) && !has_to_or_cc) {
			/* Bcc headers have been removed, and there are no remaining rcpt headers */
			DEBUG(3) debugf("adding empty 'Bcc:' header\n");
			msg->hdr_list = g_list_append(msg->hdr_list, create_header(HEAD_BCC, "Bcc:\n"));
		}
		if (!has_date) {
			DEBUG(3) debugf("adding 'Date:' header\n");
			msg->hdr_list = g_list_append(msg->hdr_list, create_header(HEAD_DATE, "Date: %s\n", rec_timestamp()));
		}
		if (!has_id) {
			DEBUG(3) debugf("adding 'Message-ID:' header\n");
			msg->hdr_list = g_list_append(msg->hdr_list,
			                              create_header(HEAD_MESSAGE_ID, "Message-ID: <%s@%s>\n", msg->uid, conf.host_name));
		}
	}

	/* Received header: */
	/* At this point because we have to know the rcpts for the 'for' part */
	if (!(flags & ACC_NO_RECVD_HDR)) {
		gchar *for_string = NULL;
		header *hdr = NULL;

		DEBUG(3) debugf("adding 'Received:' header\n");

		if (g_list_length(msg->rcpt_list) == 1) {
			address *addr = (address *) (g_list_first(msg->rcpt_list)->data);
			for_string = g_strdup_printf(" for %s", addr_string(addr));
		}

		if (msg->received_host == NULL) {
			hdr = create_header(HEAD_RECEIVED, "Received: from %s by %s with %s (%s %s) id %s%s; %s\n",
			                    passwd->pw_name, conf.host_name, prot_names[msg->received_prot],
			                    PACKAGE, VERSION, msg->uid, for_string ? for_string : "", rec_timestamp());
		} else {
#ifdef ENABLE_IDENT
			DEBUG(5) debugf("adding 'Received:' header (5)\n");
			hdr = create_header(HEAD_RECEIVED, "Received: from %s (ident=%s) by %s with %s (%s %s) id %s%s; %s\n",
			                    msg->received_host, msg->ident ? msg->ident : "unknown", conf.host_name,
			                    prot_names[msg->received_prot], PACKAGE, VERSION, msg->uid, for_string ? for_string : "",
			                    rec_timestamp());
#else
			hdr = create_header(HEAD_RECEIVED, "Received: from %s by %s with %s (%s %s) id %s%s; %s\n",
			                    msg->received_host, conf.host_name, prot_names[msg->received_prot],
			                    PACKAGE, VERSION, msg->uid, for_string ? for_string : "", rec_timestamp());
#endif
		}
		header_fold(hdr);
		msg->hdr_list = g_list_prepend(msg->hdr_list, hdr);

		if (for_string)
			g_free(for_string);
	}

	/* write message to spool: */
	/* accept is no longer responsible for this
	   if (!spool_write(msg, TRUE))
	     return AERR_NOSPOOL;
	 */
	return AERR_OK;
}

accept_error
accept_message(FILE * in, message * msg, guint flags)
{
	accept_error err;

	err = accept_message_stream(in, msg, flags);
	if (err == AERR_OK)
		err = accept_message_prepare(msg, flags);

	return err;
}
