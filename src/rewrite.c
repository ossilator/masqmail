// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#ifndef REWRITE_TEST
#include "masqmail.h"
#endif

// this does not examine conf.{not_,}local_addresses, because
// matching local parts of addresses that only pretend to be
// local would make a mess in rewrite rules.
// the sender must set such an address rather deliberately,
// so they can set the final address just as well. thus we
// don't need to support rewriting these in the first place.
static gboolean
addr_is_really_local(const gchar *dom_beg, const gchar *dom_end)
{
	if (!dom_beg) {
		return TRUE;
	}

	gchar *domain = g_strndup(dom_beg, dom_end - dom_beg);
	gboolean ret = domain_is_local(domain);
	g_free(domain);
	return ret;
}

static const replacement *
map_local_part(const gchar *local_part, const GList *table, const GList *table2)
{
	const replacement *ret = table_find_fnmatch(table, local_part);
	if (!ret) {
		ret = table_find_fnmatch(table2, local_part);
	}
	return ret;
}

static const replacement *
map_address(const gchar *loc_beg, const gchar *loc_end,
            const gchar *dom_beg, const gchar *dom_end,
            const GList *table, const GList *table2)
{
	DEBUG(5) debugf("considering '%.*s@%.*s' for rewrite\n",
	                (int)(loc_end - loc_beg), loc_beg,
	                dom_beg ? (int)(dom_end - dom_beg) : 6,
	                dom_beg ? dom_beg : "(null)");
	if (!addr_is_really_local(dom_beg, dom_end)) {
		DEBUG(5) debugf("=> not local\n");
		return NULL;
	}
	gchar *local_part = g_strndup(loc_beg, loc_end - loc_beg);
	const replacement *ret = map_local_part(local_part, table, table2);
	g_free(local_part);
	DEBUG(5) {
		if (ret) {
			debugf("=> replacement '%s'\n", ret->full_address);
		} else {
			debugf("=> not found\n");
		}
	}
	return ret;
}

static header *
map_address_header(header *hdr, const GList *table, const GList *table2)
{
	const gchar *op = hdr->header;
	const gchar *p = hdr->value;
	gchar *new_hdr = NULL;
	gboolean did_change = FALSE;

	for (;;) {
		while (*p == ',' || isspace(*p)) {  // may include folded newlines
			p++;
		}
		if (!*p) {
			break;
		}

		const gchar *loc_beg, *loc_end;
		const gchar *dom_beg, *dom_end;
		const gchar *addr_end;
		if (!parse_address_rfc822(p, &loc_beg, &loc_end, &dom_beg, &dom_end, &addr_end)) {
			g_free(new_hdr);
			return FALSE;
		}

		const replacement *rewr = map_address(
				loc_beg, loc_end, dom_beg, dom_end, table, table2);

		gchar *newer_hdr;
		if (rewr) {
			did_change = TRUE;
			if (!rewr->address->local_part) {
				// replacement local part is a wildcard, so replace only the domain.
				const char *suffix = dom_end ? dom_end : loc_end;
				newer_hdr = g_strdup_printf("%s%.*s@%s%.*s", new_hdr ? new_hdr : "",
				                            (int)(loc_end - op), op,
				                            rewr->address->domain,
				                            (int)(addr_end - suffix), suffix);
			} else if (loc_beg == p) {
				// have only addr-spec, so replace the whole of it,
				// possibly making it an angle-addr.
				const gchar *nl = *addr_end ? "" : "\n";  // the parser eats the trailing newline
				newer_hdr = g_strdup_printf("%s%.*s%s%s", new_hdr ? new_hdr : "",
				                            (int)(p - op), op, rewr->full_address, nl);
			} else {
				// have an angle-addr or comments, so replace only the addr-spec.
				const char *suffix = dom_end ? dom_end : loc_end;
				newer_hdr = g_strdup_printf("%s%.*s%s%.*s", new_hdr ? new_hdr : "",
				                            (int)(loc_beg - op), op,
				                            rewr->address->address,
				                            (int)(addr_end - suffix), suffix);
			}
		} else if (did_change) {
			newer_hdr = g_strdup_printf("%s%.*s", new_hdr, (int)(addr_end - op), op);
		} else {
			p = addr_end;
			continue;
		}
		g_free(new_hdr);
		new_hdr = newer_hdr;

		p = op = addr_end;
	}

	if (!did_change) {
		g_free(new_hdr);
		return NULL;
	}

	return create_header_raw(
			hdr->id, new_hdr, hdr->value - hdr->header);
}

void
rewrite_headers(msg_out *msgout, const connect_route *route)
{
	msgout->hdr_list = copy_header_list(msgout->msg->hdr_list);
	gboolean changed = FALSE;

	foreach_mut (header *hdr, hdr_node, msgout->hdr_list) {
		GList *table;
		if (hdr->id == HEAD_FROM) {
			table = route->map_h_from_addresses;
		} else if (hdr->id == HEAD_SENDER) {
			table = route->map_h_sender_addresses;
		} else if (hdr->id == HEAD_REPLY_TO) {
			table = route->map_h_reply_to_addresses;
		} else if (hdr->id == HEAD_MAIL_FOLLOWUP_TO) {
			table = route->map_h_mail_followup_to_addresses;
		} else {
			continue;
		}
		GList *table2 = route->map_outgoing_addresses;
		if (!table && !table2) {
			DEBUG(5) debugf("no rewrite rules for header '%.*s'\n",
			                (int)(hdr->value - hdr->header), hdr->header);
			continue;
		}
		header *new_hdr = map_address_header(hdr, table, table2);
		if (!new_hdr) {
			continue;
		}
		hdr->ref_count--;
		hdr_node->data = new_hdr;
		changed = TRUE;
	}

	if (!changed) {
		destroy_header_list(msgout->hdr_list);
		msgout->hdr_list = NULL;
	}
	DEBUG(5) debugf("rewrite_headers() returning\n");
}

void
rewrite_return_path(msg_out *msgout, const connect_route *route)
{
	const message *msg = msgout->msg;
	DEBUG(5) debugf("considering return path '%s' for rewriting\n",
	                msg->return_path->address);
	if (!route->map_return_path_addresses && !route->map_outgoing_addresses) {
		DEBUG(5) debugf("=> no rules\n");
		return;
	}
	if (!domain_is_local(msg->return_path->domain)) {
		DEBUG(5) debugf("=> not local\n");
		return;
	}
	const replacement *ret_path = map_local_part(msg->return_path->local_part,
			route->map_return_path_addresses, route->map_outgoing_addresses);
	if (!ret_path) {
		DEBUG(5) debugf("=> no match\n");
		return;
	}
	DEBUG(5) debugf("=> replacement '%s'\n", ret_path->address->address);
	msgout->return_path = create_address_raw(
			ret_path->address->local_part ?
					ret_path->address->local_part :
					msg->return_path->local_part,
			ret_path->address->domain[0] ?
					ret_path->address->domain :
					msg->return_path->domain);
}
