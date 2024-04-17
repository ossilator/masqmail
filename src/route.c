// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <fnmatch.h>

static msgout_perhost*
create_msgout_perhost(gchar *host)
{
	msgout_perhost *mo_ph = g_malloc(sizeof(msgout_perhost));
	mo_ph->host = host;
	mo_ph->msgout_list = NULL;
	return mo_ph;
}

static void
destroy_msgout_part(msg_out *mo)
{
	/* the rcpt_list is owned by the msgout's, but not the rcpt's themselves */
	g_list_free(mo->rcpt_list);
	g_free(mo);
}

void
destroy_msgout_perhost(msgout_perhost *mo_ph)
{
	g_list_free_full(mo_ph->msgout_list, (GDestroyNotify) destroy_msgout_part);
	g_free(mo_ph);
}

static void
rewrite_headers(msg_out *msgout, connect_route *route)
{
	msgout->hdr_list = g_list_copy(msgout->msg->hdr_list);

	/* map from addresses */
	if (route->map_h_from_addresses != NULL) {
		GList *hdr_node;
		foreach(msgout->hdr_list, hdr_node) {
			header *hdr = (header *) (hdr_node->data);
			if (hdr->id == HEAD_FROM) {
				header *new_hdr = copy_header(hdr);
				if (map_address_header(new_hdr, route->map_h_from_addresses)) {
					hdr_node->data = new_hdr;
					/* we need this list only to carefully free the extra headers: */
					msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
				} else
					g_free(new_hdr);
			}
		}
	}

	/* map reply-to addresses */
	if (route->map_h_reply_to_addresses != NULL) {
		GList *hdr_node;
		foreach(msgout->hdr_list, hdr_node) {
			header *hdr = (header *) (hdr_node->data);
			if (hdr->id == HEAD_REPLY_TO) {
				header *new_hdr = copy_header(hdr);
				if (map_address_header
					(new_hdr, route->map_h_reply_to_addresses)) {
					hdr_node->data = new_hdr;
					/* we need this list only to carefully free the extra headers: */
					msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
				} else
					g_free(new_hdr);
			}
		}
	}

	/* map Mail-Followup-To addresses */
	if (route->map_h_mail_followup_to_addresses != NULL) {
		GList *hdr_node;
		foreach(msgout->hdr_list, hdr_node) {
			header *hdr = (header *) (hdr_node->data);
			if (strncasecmp(hdr->header, "Mail-Followup-To", 16) == 0) {
				header *new_hdr = copy_header(hdr);
				if (map_address_header(new_hdr, route->map_h_mail_followup_to_addresses)) {
					hdr_node->data = new_hdr;
					/* we need this list only to carefully free the extra headers: */
					msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
				} else
					g_free(new_hdr);
			}
		}
	}

	if (msgout->xtra_hdr_list == NULL) {
		/* nothing was changed */
		g_list_free(msgout->hdr_list);
		msgout->hdr_list = NULL;
	}
	DEBUG(5) debugf("rewrite_headers() returning\n");
}

static void
filter_rcpts(GList *patterns, gboolean keep_matching, GList **rcpt_list)
{
	GList *rcpt_node;
	GList *out_list = NULL;

	foreach (*rcpt_list, rcpt_node) {
		recipient *rcpt = rcpt_node->data;
		gboolean matched = FALSE;
		GList *pat_node = NULL;
		foreach (patterns, pat_node) {
			address *pat = (address *) (pat_node->data);
			if (!fnmatch(pat->domain, rcpt->address->domain, FNM_CASEFOLD) &&
			    !fnmatch(pat->local_part, rcpt->address->local_part, 0)) {  /* TODO: match local_part caseless? */
				matched = TRUE;
				break;
			}
		}
		if (matched == keep_matching) {
			out_list = g_list_append(out_list, rcpt);
		}
	}
	g_list_free(*rcpt_list);
	*rcpt_list = out_list;
}

// Local domains are NOT regarded here, these should be sorted out earlier.
void
route_filter_rcpts(connect_route *route, GList **rcpt_list)
{
	// sort out those domains that can be sent over this connection:
	if (route->allowed_recipients) {
		DEBUG(5) debugf("testing for route->allowed_recipients\n");
		filter_rcpts(route->allowed_recipients, TRUE, rcpt_list);
	} else {
		DEBUG(5) debugf("route->allowed_recipients == NULL\n");
	}

	// sort out those domains that cannot be sent over this connection:
	if (route->denied_recipients) {
		DEBUG(5) debugf("testing for route->denied_recipients\n");
		filter_rcpts(route->denied_recipients, FALSE, rcpt_list);
	} else {
		DEBUG(5) debugf("route->denied_recipients == NULL\n");
	}
}

void
split_rcpts(GList *rcpt_list, GList **local_rcpts, GList **remote_rcpts)
{
	GList *rcpt_node;

	foreach(rcpt_list, rcpt_node) {
		recipient *rcpt = rcpt_node->data;
		if (addr_is_local(rcpt->address)) {
			*local_rcpts = g_list_append(*local_rcpts, rcpt);
		} else {
			*remote_rcpts = g_list_append(*remote_rcpts, rcpt);
		}
	}
}

static gint
_g_list_addrcmp(gconstpointer pattern, gconstpointer addr)
{
	int res;
	address *patternaddr = (address*) pattern;
	address *stringaddr = (address*) addr;

	DEBUG(6) debugf("_g_list_addrcmp: pattern `%s' `%s' on string `%s' `%s'\n",
	                patternaddr->local_part, patternaddr->domain,
	                stringaddr->local_part, stringaddr->domain);
	/* TODO: check if we should match here dependent on caseless_matching */
	res = fnmatch(patternaddr->local_part, stringaddr->local_part, 0);
	if (res != 0) {
		DEBUG(6) debugf("_g_list_addrcmp: ... failed on local_part\n");
		return res;
	}
	res = fnmatch(patternaddr->domain, stringaddr->domain, FNM_CASEFOLD);
	DEBUG(6) debugf("_g_list_addrcmp: ... %s\n", (res==0) ? "matched" : "failed on domain");
	return res;
}

gboolean
route_sender_is_allowed(connect_route *route, address *ret_path)
{
	if (route->denied_senders && g_list_find_custom(route->denied_senders, ret_path, _g_list_addrcmp)) {
		return FALSE;
	}
	if (route->allowed_senders) {
		if (g_list_find_custom(route->allowed_senders, ret_path, _g_list_addrcmp)) {
			return TRUE;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}

gboolean
route_from_hdr_is_allowed(connect_route *route, address *addr)
{
	if (route->denied_from_hdrs && g_list_find_custom(route->denied_from_hdrs, addr, _g_list_addrcmp)) {
		return FALSE;
	}
	if (route->allowed_from_hdrs) {
		if (g_list_find_custom(route->allowed_from_hdrs, addr,
				_g_list_addrcmp)) {
			return TRUE;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}


msg_out*
route_prepare_msgout(connect_route *route, msg_out *msgout)
{
	message *msg = msgout->msg;
	GList *rcpt_list = msgout->rcpt_list;

	if (rcpt_list != NULL) {
		/* found a few */
		DEBUG(5) {
			GList *node;
			debugf("rcpts for routed delivery, route = %s, id = %s\n", route->name, msg->uid);
			foreach(rcpt_list, node) {
				recipient *rcpt = node->data;
				debugf("  rcpt for routed delivery: <%s>\n", rcpt->address->address);
			}
		}

		/*
		**  rewrite return path if there is a table, use that
		**  if an address is found and if it has a domain, use that
		*/
		if (route->map_return_path_addresses) {
			address *ret_path = NULL;
			DEBUG(5) debugf("looking up %s in map_return_path_addresses\n", msg->return_path->local_part);
			ret_path = (address *) table_find_fnmatch(route->map_return_path_addresses, msg->return_path->local_part);
			if (ret_path) {
				DEBUG(5) debugf("found <%s>\n", ret_path->address);
				if (!ret_path->domain[0])
					ret_path->domain = msg->return_path->domain;
				msgout->return_path = copy_address(ret_path);
			}
		}
		rewrite_headers(msgout, route);

		return msgout;
	}
	return NULL;
}

/*
**  put msgout's is msgout_list into bins (msgout_perhost structs) for each
**  host. Used if there is no mail_host.
*/
GList*
route_msgout_list(GList *msgout_list)
{
	GList *mo_ph_list = NULL;
	GList *msgout_node;

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		msg_out *msgout_new;
		GList *rcpt_list = msgout->rcpt_list;
		GList *rcpt_node;

		foreach(rcpt_list, rcpt_node) {
			recipient *rcpt = rcpt_node->data;
			msgout_perhost *mo_ph = NULL;
			GList *mo_ph_node = NULL;

			/* search host in mo_ph_list */
			foreach(mo_ph_list, mo_ph_node) {
				mo_ph = (msgout_perhost *) (mo_ph_node->data);
				if (strcasecmp(mo_ph->host, rcpt->address->domain) == 0)
					break;
			}
			if (mo_ph_node != NULL) {
				/* there is already a rcpt for this host */
				msg_out *msgout_last = (msg_out *) ((g_list_last(mo_ph->msgout_list))->data);
				if (msgout_last->msg == msgout->msg) {
					/*
					**  if it is also the same message,
					**  it must be the last one
					**  appended to mo_ph->msgout_list
					**  (since outer loop goes through
					**  msgout_list)
					*/
					msgout_last->rcpt_list = g_list_append(msgout_last->rcpt_list, rcpt);
				} else {
					/* if not, we append a new msgout */
					/* make a copy of msgout */
					msgout_new = create_msg_out(msgout->msg);
					msgout_new->return_path = msgout->return_path;
					msgout_new->hdr_list = msgout->hdr_list;

					/* append our rcpt to it */
					/* It is the 1st rcpt for this msg to this host, therefore we safely give NULL */
					msgout_new->rcpt_list = g_list_append(NULL, rcpt);
					mo_ph->msgout_list = g_list_append(mo_ph->msgout_list, msgout_new);
				}
			} else {
				/* this rcpt to goes to another host */
				mo_ph = create_msgout_perhost(rcpt->address->domain);
				mo_ph_list = g_list_append(mo_ph_list, mo_ph);

				/* make a copy of msgout */
				msgout_new = create_msg_out(msgout->msg);
				msgout_new->return_path = msgout->return_path;
				msgout_new->hdr_list = msgout->hdr_list;

				/* append our rcpt to it */
				/* It is the 1st rcpt for this msg to this host, therefore we safely give NULL */
				msgout_new->rcpt_list = g_list_append(NULL, rcpt);
				mo_ph->msgout_list = g_list_append(mo_ph->msgout_list, msgout_new);
			}  /* if mo_ph != NULL */
		}  /* foreach(rcpt_list, ... */
	}  /* foreach(msgout_list, ... */

	return mo_ph_list;
}
