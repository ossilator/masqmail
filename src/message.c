// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

message*
create_message()
{
	message *msg = (message *) g_malloc0(sizeof(message));
	msg->data_size = -1;
	return msg;
}

/*
**  This function is currently (0.2.24) only used for client side SMTP
**  SIZE support (RFC 1870). The flag is_smtp is always true therefore.
**
**  Their definition of the message size in RFC 1870 is:
**
**      The message size is defined as the number of octets, including
**      CR-LF pairs, but not the SMTP DATA command's terminating dot
**      or doubled quoting dots, to be transmitted by the SMTP client
**      after receiving reply code 354 to the DATA command.
**
**  l_cnt (line count) covers '\r' characters which are not present in
**  masqmail's internal format. Dots are also not stuffed in the
**  internal format. Dot-stuffing is ignored in the size.
*/
gssize
msg_calc_size(message *msg, gboolean is_smtp)
{
	GList *node;
	gint l_cnt = 0;  /* line count (we need to add so many '\r' for SMTP) */
	gssize c_cnt = 0;  /* character count */

	/* message header size */
	if (msg->hdr_list) {
		for (node = g_list_first(msg->hdr_list); node; node = g_list_next(node)) {
			if (node->data) {
				header *hdr = (header *) (node->data);
				if (hdr->header) {
					char *p = hdr->header;
					while (*p) {
						if (*p++ == '\n')
							l_cnt++;
						c_cnt++;
					}
				}
			}
		}
	}

	/* empty line separating headers from data: */
	c_cnt++;
	l_cnt++;

	/* message data size */
	if (msg->data_list) {
		for (node = g_list_first(msg->data_list); node; node = g_list_next(node)) {
			if (node->data) {
				char *p = node->data;
				while (*p) {
					if (*p++ == '\n')
						l_cnt++;
					c_cnt++;
				}
			}
		}
	}

	return is_smtp ? c_cnt + l_cnt : c_cnt;
}

void
destroy_ptr_list(GList *list)
{
	g_list_free_full(list, g_free);
}

void
msg_free_data(message *msg)
{
	destroy_ptr_list(msg->data_list);
	msg->data_list = NULL;
}

void
destroy_message(message *msg)
{
	if (!msg) {
		return;
	}

	g_free(msg->uid);
	g_free(msg->ident);
	destroy_address(msg->return_path);

	destroy_recipient_list(msg->rcpt_list);
	destroy_recipient_list(msg->non_rcpt_list);
	destroy_header_list(msg->hdr_list);

	msg_free_data(msg);

	g_free(msg);
}

void
destroy_msg_list(GList *msg_list)
{
	g_list_free_full(msg_list, (GDestroyNotify) destroy_message);
}

msg_out*
create_msg_out(message *msg)
{
	msg_out *msgout = g_malloc0(sizeof(msg_out));
	msgout->msg = msg;
	return msgout;
}

msg_out*
clone_msg_out(msg_out *msgout_orig)
{
	if (!msgout_orig) {
		return NULL;
	}
	msg_out *msgout = create_msg_out(msgout_orig->msg);
	if (msgout_orig->return_path)
		msgout->return_path = copy_address(msgout_orig->return_path);
	if (msgout_orig->hdr_list)
		msgout->hdr_list = g_list_copy(msgout_orig->hdr_list);
	/* FIXME: if this lives longer than the original
	   and we access one of the xtra hdrs, we will segfault
	   or cause some weird bugs: */
	msgout->xtra_hdr_list = NULL;
	msgout->rcpt_list = copy_recipient_list(msgout_orig->rcpt_list);
	return msgout;
}

void
destroy_msg_out(msg_out *msgout)
{
	if (msgout) {
		if (msgout->return_path)
			destroy_address(msgout->return_path);
		destroy_recipient_list(msgout->rcpt_list);
		g_list_free(msgout->hdr_list);
		destroy_header_list(msgout->xtra_hdr_list);
		g_free(msgout);
	}
}

void
destroy_msg_out_list(GList *msgout_list)
{
	g_list_free_full(msgout_list, (GDestroyNotify) destroy_msg_out);
}
