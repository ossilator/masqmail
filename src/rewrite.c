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

gboolean
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
	if (did_change) {
		g_free(hdr->header);
		hdr->header = new_hdr;
	} else {
		g_free(new_hdr);
	}

	return did_change;
}
