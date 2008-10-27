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

message*
create_message()
{
	message *msg = (message *) g_malloc(sizeof(message));
	if (msg) {
		memset(msg, 0, sizeof(message));
		msg->data_size = -1;
	}
	return msg;
}

gint
msg_calc_size(message * msg, gboolean is_smtp)
{
	GList *node;
	gint l_cnt = 0, c_cnt = 0;

	/* header size */
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

	/* data size */
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
msg_free_data(message * msg)
{
	GList *node;

	if (msg->data_list) {
		for (node = g_list_first(msg->data_list); node; node = g_list_next(node)) {
			if (node->data)
				g_free(node->data);
		}
		g_list_free(msg->data_list);
		msg->data_list = NULL;
	}
}

void
destroy_message(message * msg)
{
	GList *node;

	if (msg->uid)
		g_free(msg->uid);
	if (msg->ident)
		g_free(msg->ident);
	if (msg->return_path)
		g_free(msg->return_path);

	if (msg->rcpt_list) {
		for (node = g_list_first(msg->rcpt_list); node; node = g_list_next(node)) {
			if (node->data)
				g_free(node->data);
		}
		g_list_free(msg->rcpt_list);
	}
	if (msg->hdr_list) {
		for (node = g_list_first(msg->hdr_list); node; node = g_list_next(node)) {
			if (node->data) {
				header *hdr = (header *) (node->data);
				if (hdr->header)
					g_free(hdr->header);
				g_free(node->data);
			}
		}
		g_list_free(msg->hdr_list);
	}

	if (msg->full_sender_name)
		g_free(msg->full_sender_name);

	msg_free_data(msg);

	g_free(msg);
}

void
destroy_msg_list(GList * msg_list)
{
	GList *msg_node;

	foreach(msg_list, msg_node) {
		message *msg = (message *) (msg_node->data);
		destroy_message(msg);
	}
	g_list_free(msg_list);
}

msg_out*
create_msg_out(message * msg)
{
	msg_out *msgout = NULL;

	msgout = g_malloc(sizeof(msg_out));
	if (msgout) {
		msgout->msg = msg;
		msgout->return_path = NULL;
		msgout->rcpt_list = NULL;

		msgout->hdr_list = NULL;
		msgout->xtra_hdr_list = NULL;
	}
	return msgout;
}

msg_out*
clone_msg_out(msg_out * msgout_orig)
{
	if (msgout_orig) {
		msg_out *msgout = create_msg_out(msgout_orig->msg);
		if (msgout) {
			msgout->msg = msgout_orig->msg;
			if (msgout_orig->return_path)
				msgout->return_path = copy_address(msgout_orig->return_path);
			if (msgout_orig->hdr_list)
				msgout->hdr_list = g_list_copy(msgout_orig->hdr_list);
			/* FIXME: if this lives longer than the original
			   and we access one of the xtra hdrs, we will segfault
			   or cause some weird bugs: */
			msgout->xtra_hdr_list = NULL;
			if (msgout_orig->rcpt_list)
				msgout->rcpt_list = g_list_copy(msgout_orig->rcpt_list);
		}
		return msgout;
	}
	return NULL;
}

GList*
create_msg_out_list(GList * msg_list)
{
	GList *msgout_list = NULL;
	GList *msg_node;

	foreach(msg_list, msg_node) {
		message *msg = (message *) (msg_node->data);
		msgout_list = g_list_append(msgout_list, create_msg_out(msg));
	}
	return msgout_list;
}

void
destroy_msg_out(msg_out * msgout)
{
	if (msgout) {
		if (msgout->return_path)
			destroy_address(msgout->return_path);
		if (msgout->hdr_list)
			g_list_free(msgout->hdr_list);
		if (msgout->xtra_hdr_list) {
			GList *hdr_node;
			foreach(msgout->xtra_hdr_list, hdr_node) {
				header *hdr = (header *) (hdr_node->data);
				destroy_header(hdr);
			}
			g_list_free(msgout->xtra_hdr_list);
		}
		g_free(msgout);
	}
}

void
destroy_msg_out_list(GList * msgout_list)
{
	GList *msgout_node;

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		destroy_msg_out(msgout);
	}
	g_list_free(msgout_list);
}
