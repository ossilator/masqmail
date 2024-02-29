// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#ifndef REWRITE_TEST
#include "masqmail.h"
#endif

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
