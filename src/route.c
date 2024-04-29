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
filter_rcpts(GList *patterns, gboolean keep_matching, GList **rcpt_list)
{
	GList *out_list = NULL;

	foreach (recipient *rcpt, *rcpt_list) {
		gboolean matched = FALSE;
		foreach (address *pat, patterns) {
			if (!fnmatch(pat->domain, rcpt->address->domain, FNM_CASEFOLD) &&
			    !fnmatch(pat->local_part, rcpt->address->local_part, 0)) {  /* TODO: match local_part caseless? */
				matched = TRUE;
				break;
			}
		}
		if (matched == keep_matching) {
			out_list = g_list_append(out_list, rcpt);
			rcpt->ref_count++;
		}
	}
	destroy_recipient_list(*rcpt_list);
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

static gboolean
is_non_recipient(recipient *addr, GList *non_rcpt_list)
{
	foreach (recipient *non_addr, non_rcpt_list) {
		if (addr_isequal(addr->address, non_addr->address, conf.localpartcmp)) {
			return TRUE;
		}
	}
	return FALSE;
}

void
split_rcpts(GList *rcpt_list, GList *non_rcpt_list,
            GList **local_rcpts, GList **remote_rcpts)
{
	foreach (recipient *rcpt, rcpt_list) {
		if (addr_is_finished(rcpt)) {
			// broken alias expansion
		} else if (addr_is_alias(rcpt)) {
			// is an expanded alias; deliver only to the expansions
			split_rcpts(rcpt->children, non_rcpt_list, local_rcpts, remote_rcpts);
		} else if (is_non_recipient(rcpt, non_rcpt_list)) {
			// omit already delivered addresses
		} else if (addr_is_local(rcpt->address)) {
			*local_rcpts = g_list_append(*local_rcpts, rcpt);
			rcpt->ref_count++;
		} else {
			*remote_rcpts = g_list_append(*remote_rcpts, rcpt);
			rcpt->ref_count++;
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
	GList *rcpt_list = msgout->rcpt_list;

	if (rcpt_list != NULL) {
		/* found a few */
		DEBUG(5) {
			debugf("rcpts for routed delivery, route = %s, id = %s\n",
			       route->name, msgout->msg->uid);
			foreach (recipient *rcpt, rcpt_list) {
				debugf("  rcpt for routed delivery: <%s>\n", rcpt->address->address);
			}
		}

		rewrite_return_path(msgout, route);
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

	foreach (msg_out *msgout, msgout_list) {
		msg_out *msgout_new;
		GList *rcpt_list = msgout->rcpt_list;
		foreach (recipient *rcpt, rcpt_list) {
			msgout_perhost *mo_ph = NULL;
			/* search host in mo_ph_list */
			foreach (msgout_perhost *tmp_mo_ph, mo_ph_list) {
				if (!strcasecmp(tmp_mo_ph->host, rcpt->address->domain)) {
					mo_ph = tmp_mo_ph;
					break;
				}
			}
			if (mo_ph != NULL) {
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
					continue;
				}
				/* if not, we append a new msgout */
			} else {
				/* this rcpt to goes to another host */
				mo_ph = create_msgout_perhost(rcpt->address->domain);
				mo_ph_list = g_list_append(mo_ph_list, mo_ph);
			}  /* if mo_ph != NULL */

			/* make a copy of msgout */
			msgout_new = create_msg_out(msgout->msg);
			msgout_new->return_path = msgout->return_path;
			msgout_new->hdr_list = msgout->hdr_list;

			/* append our rcpt to it. */
			/* It is the 1st rcpt for this msg to this host, therefore we safely give NULL */
			msgout_new->rcpt_list = g_list_append(NULL, rcpt);
			mo_ph->msgout_list = g_list_append(mo_ph->msgout_list, msgout_new);
		}  // foreach rcpt_list
	}  // foreach msgout_list

	return mo_ph_list;
}
