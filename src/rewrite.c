// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#ifndef REWRITE_TEST
#include "masqmail.h"
#endif

#include <fnmatch.h>

gboolean
set_address_header_domain(header *hdr, gchar *domain)
{
	gchar *p = hdr->value;
	gchar *new_hdr = g_strndup(hdr->header, hdr->value - hdr->header);
	gint tmp;
	gchar *loc_beg, *loc_end;
	gchar *dom_beg, *dom_end;
	gchar *addr_end;
	gchar *rewr_string;
	gchar *left, *right;

	while (*p) {
		if (!parse_address_rfc822(p, &loc_beg, &loc_end, &dom_beg, &dom_end, &addr_end)) {
			return FALSE;
		}

		if (dom_beg) {
			left = g_strndup(p, dom_beg - p);
			right = g_strndup(dom_end, addr_end - dom_end);

			rewr_string = g_strconcat(left, domain, right, NULL);
		} else {
			left = g_strndup(p, loc_end - p);
			right = g_strndup(loc_end, addr_end - loc_end);

			rewr_string = g_strconcat(left, "@", domain, right, NULL);
		}
		g_free(left);
		g_free(right);

		p = addr_end;
		if (*p == ',') {
			p++;
		}
		new_hdr = g_strconcat(new_hdr, rewr_string, *p != '\0' ? "," : NULL, NULL);
	}

	tmp = (hdr->value - hdr->header);
	g_free(hdr->header);
	hdr->header = new_hdr;
	hdr->value = hdr->header + tmp;

	return TRUE;
}

gboolean
map_address_header(header *hdr, GList *table)
{
	GList *addr_list = addr_list_append_rfc822(NULL, hdr->value, conf.host_name);
	GList *addr_node;
	gchar *new_hdr = g_strndup(hdr->header, hdr->value - hdr->header);
	gboolean did_change = FALSE;

	foreach(addr_list, addr_node) {
		address *addr = (address *) (addr_node->data);
		gchar *rewr_string = (gchar *) table_find_fnmatch(table, addr->local_part);

		if (rewr_string) {
			did_change = TRUE;
		} else {
			rewr_string = addr->address;
		}

		if (rewr_string) {
			new_hdr = g_strconcat(new_hdr, rewr_string, g_list_next(addr_node) ? "," : "\n", NULL);
		}
	}
	if (did_change) {
		g_free(hdr->header);
		hdr->header = new_hdr;
	} else {
		g_free(new_hdr);
	}

	return did_change;
}
