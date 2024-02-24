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
	if (mo_ph) {
		mo_ph->host = g_strdup(host);
		mo_ph->msgout_list = NULL;
	}
	return mo_ph;
}

void
destroy_msgout_perhost(msgout_perhost *mo_ph)
{
	GList *mo_node;

	foreach(mo_ph->msgout_list, mo_node) {
		msg_out *mo = (msg_out *) (mo_node->data);
		/* the rcpt_list is owned by the msgout's, but not the rcpt's themselves */
		g_list_free(mo->rcpt_list);
		g_free(mo);
	}
	g_list_free(mo_ph->msgout_list);
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

/*
**  Split a recipient list into the three groups:
**  - local recipients
**  - those maching the patterns
**  - those not matching the patterns
**  If patterns is NULL: only splitting between local and others is done.
*/
static void
split_rcpts(GList *rcpt_list, GList *patterns, GList **rl_local,
		GList **rl_matching, GList **rl_others)
{
	GList *rcpt_node;
	GList *pat_node = NULL;
	address *rcpt = NULL;

	if (rcpt_list == NULL)
		return;

	foreach(rcpt_list, rcpt_node) {
		rcpt = (address *) (rcpt_node->data);
		pat_node = NULL;

		if (addr_is_local(rcpt)) {
			if (rl_local)
				*rl_local = g_list_append(*rl_local, rcpt);
		} else {
			/*
			**  if patterns is NULL, pat_node will be NULL,
			**  hence all non-locals are put to others
			*/
			foreach(patterns, pat_node) {
				address *pat = (address *) (pat_node->data);
				if (fnmatch(pat->domain, rcpt->domain, FNM_CASEFOLD)==0 && fnmatch(pat->local_part, rcpt->local_part, 0)==0) {  /* TODO: match local_part caseless? */
					break;
				}
			}
			if (pat_node) {
				if (rl_matching)
					*rl_matching = g_list_append(*rl_matching, rcpt);
			} else {
				if (rl_others)
					*rl_others = g_list_append(*rl_others, rcpt);
			}
		}
	}
}

/*
**  Return a new list of the local rcpts in the rcpt_list
**  TODO: This function is almost exactly the same as remote_rcpts(). Merge?
*/
GList*
local_rcpts(GList *rcpt_list)
{
	GList *rcpt_node;
	GList *local_rcpts = NULL;
	address *rcpt = NULL;

	if (!rcpt_list) {
		return NULL;
	}
	foreach(rcpt_list, rcpt_node) {
		rcpt = (address *) (rcpt_node->data);
		if (addr_is_local(rcpt)) {
			local_rcpts = g_list_append(local_rcpts, rcpt);
		}
	}
	return local_rcpts;
}

/*
**  Return a new list of non-local rcpts in the rcpt_list
**  TODO: This function is almost exactly the same as local_rcpts(). Merge?
*/
GList*
remote_rcpts(GList *rcpt_list)
{
	GList *rcpt_node;
	GList *remote_rcpts = NULL;
	address *rcpt = NULL;

	if (!rcpt_list) {
		return NULL;
	}
	foreach(rcpt_list, rcpt_node) {
		rcpt = (address *) (rcpt_node->data);
		if (!addr_is_local(rcpt)) {
			remote_rcpts = g_list_append(remote_rcpts, rcpt);
		}
	}
	return remote_rcpts;
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

/*
**  Make lists of matching/not matching rcpts.
**  Local domains are NOT regared here, these should be sorted out previously
*/
void
route_split_rcpts(connect_route *route, GList *rcpt_list, GList **p_rcpt_list, GList **p_non_rcpt_list)
{
	GList *tmp_list = NULL;
	/* sort out those domains that can be sent over this connection: */
	if (route->allowed_recipients) {
		DEBUG(5) debugf("testing for route->allowed_recipients\n");
		split_rcpts(rcpt_list, route->allowed_recipients, NULL, &tmp_list, p_non_rcpt_list);
	} else {
		DEBUG(5) debugf("route->allowed_recipients == NULL\n");
		tmp_list = g_list_copy(rcpt_list);
	}

	/* sort out those domains that cannot be sent over this connection: */
	split_rcpts(tmp_list, route->denied_recipients, NULL, p_non_rcpt_list, p_rcpt_list);
	g_list_free(tmp_list);
}

gboolean
route_from_hdr_is_allowed(connect_route *route, char *from_hdr)
{
	address *addr = create_address_qualified(from_hdr, FALSE,
			conf.host_name);
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
				address *rcpt = (address *) (node->data);
				debugf("  rcpt for routed delivery: <%s@%s>\n",
				       rcpt->local_part, rcpt->domain);
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
				DEBUG(5) debugf("found <%s@%s>\n", ret_path->local_part, ret_path->domain);
				if (ret_path->domain == NULL)
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
**  route param is not used, we leave it here because that may change.
*/
GList*
route_msgout_list(connect_route *route, GList *msgout_list)
{
	GList *mo_ph_list = NULL;
	GList *msgout_node;

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		msg_out *msgout_new;
		GList *rcpt_list = msgout->rcpt_list;
		GList *rcpt_node;

		foreach(rcpt_list, rcpt_node) {
			address *rcpt = rcpt_node->data;
			msgout_perhost *mo_ph = NULL;
			GList *mo_ph_node = NULL;

			/* search host in mo_ph_list */
			foreach(mo_ph_list, mo_ph_node) {
				mo_ph = (msgout_perhost *) (mo_ph_node->data);
				if (strcasecmp(mo_ph->host, rcpt->domain) == 0)
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
				mo_ph = create_msgout_perhost(rcpt->domain);
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
