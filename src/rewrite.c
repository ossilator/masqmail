// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#ifndef REWRITE_TEST
#include "masqmail.h"
#endif

static gchar *
map_address(const gchar *loc_beg, const gchar *loc_end,
            GList *table)
{
	DEBUG(5) debugf("considering '%.*s' for rewrite\n",
	                (int)(loc_end - loc_beg), loc_beg);
	gchar *local_part = g_strndup(loc_beg, loc_end - loc_beg);
	gchar *ret = table_find_fnmatch(table, local_part);
	g_free(local_part);
	DEBUG(5) {
		if (ret) {
			debugf("=> replacement '%s'\n", ret);
		} else {
			debugf("=> not found\n");
		}
	}
	return ret;
}

static header *
map_address_header(header *hdr, GList *table)
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

		gchar *rewr_string = map_address(loc_beg, loc_end, table);

		gchar *newer_hdr;
		if (rewr_string) {
			did_change = TRUE;
			const gchar *nl = *addr_end ? "" : "\n";  // the parser eats the trailing newline
			newer_hdr = g_strdup_printf("%s%.*s%s%s", new_hdr ? new_hdr : "",
			                            (int)(p - op), op, rewr_string, nl);
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
	msgout->hdr_list = g_list_copy(msgout->msg->hdr_list);

	GList *hdr_node;
	foreach (msgout->hdr_list, hdr_node) {
		header *hdr = hdr_node->data;
		GList *table;
		if (hdr->id == HEAD_FROM) {
			table = route->map_h_from_addresses;
		} else if (hdr->id == HEAD_REPLY_TO) {
			table = route->map_h_reply_to_addresses;
		} else if (hdr->id == HEAD_MAIL_FOLLOWUP_TO) {
			table = route->map_h_mail_followup_to_addresses;
		} else {
			continue;
		}
		if (!table) {
			DEBUG(5) debugf("no rewrite rules for header '%.*s'\n",
			                (int)(hdr->value - hdr->header), hdr->header);
			continue;
		}
		header *new_hdr = map_address_header(hdr, table);
		if (!new_hdr) {
			continue;
		}
		hdr_node->data = new_hdr;
		// we need this list only to carefully free the extra headers:
		msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
	}

	if (msgout->xtra_hdr_list == NULL) {
		// nothing was changed
		g_list_free(msgout->hdr_list);
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
	if (!route->map_return_path_addresses) {
		DEBUG(5) debugf("=> no rules\n");
		return;
	}
	const address *ret_path = table_find_fnmatch(
			route->map_return_path_addresses, msg->return_path->local_part);
	if (!ret_path) {
		DEBUG(5) debugf("=> no match\n");
		return;
	}
	DEBUG(5) debugf("=> replacement '%s'\n", ret_path->address);
	msgout->return_path = create_address_raw(
			ret_path->local_part,
			ret_path->domain[0] ?
					ret_path->domain :
					msg->return_path->domain);
}
