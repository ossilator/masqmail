// SPDX-FileCopyrightText: (C) 2000-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <fnmatch.h>

static GList*
parse_list(const gchar *line)
{
	GList *list = NULL;
	gchar buf[256];
	gchar *q;

	const gchar *p = line;
	while (*p) {
		q = buf;
		while (isspace(*p)) {
			p++;
		}
		if (*p != '"') {
			while (*p && (*p != ',') && (q < buf + 255)) {
				*(q++) = *(p++);
			}
			*q = '\0';
		} else {
			gboolean escape = FALSE;
			p++;
			while (*p && (*p != '"' || escape) && (q < buf+255)) {
				if ((*p == '\\') && !escape) {
					escape = TRUE;
				} else {
					escape = FALSE;
					*(q++) = *p;
				}
				p++;
			}
			*q = '\0';
			while (*p && (*p != ',')) {
				p++;
			}
		}
		list = g_list_append(list, g_strdup(g_strchomp(buf)));
		if (*p) {
			p++;
		}
	}
	return list;
}

static gboolean
expand_one(const GList *globalias_table, const GList *alias_table, recipient *addr)
{
	GList *val_list;

	if (!addr_is_local(addr->address)) {
		DEBUG(5) debugf("alias: '%s' is non-local, hence completed\n",
		                addr->address->address);
		return TRUE;
	}

	/* expand the local alias */
	DEBUG(6) debugf("alias: '%s' is local and will get expanded\n",
	                addr->address->address);

	const gchar *repl;
	if (conf.localpartcmp == strcasecmp ||
	    // postmaster must always be matched caselessly, see RFCs 5321 and 5322
	    strcasecmp(addr->address->local_part, "postmaster") == 0) {
		repl = table_find_fnmatch_casefold(globalias_table, addr->address->address);
		if (!repl) {
			repl = table_find_casefold(alias_table, addr->address->local_part);
		}
	} else {
		// FIXME: the domain is matched case-sensitively as well
		repl = table_find_fnmatch(globalias_table, addr->address->address);
		if (!repl) {
			repl = table_find(alias_table, addr->address->local_part);
		}
	}
	if (!repl) {
		DEBUG(5) debugf("alias: '%s' is fully expanded, hence completed\n",
		                addr->address->address);
		return TRUE;
	}

	DEBUG(5) debugf("alias: '%s' -> '%s'\n", addr->address->address, repl);
	addr_mark_alias(addr);

	gboolean ok = TRUE;
	val_list = parse_list(repl);
	foreach (const gchar *val, val_list) {
		recipient *alias_addr;

		DEBUG(6) debugf("alias: processing '%s'\n", val);

		if (*val == '\\') {
			DEBUG(5) debugf("alias: '%s' is marked as final, hence completed\n", val);
			alias_addr = create_recipient(val + 1, conf.host_name);
			if (!alias_addr) {
				logwrite(LOG_ERR, "alias '%s' expands to invalid address '%s': %s\n",
				         addr->address->address, val + 1, parse_error);
				ok = FALSE;
				continue;
			}
			DEBUG(6) debugf("alias:     address generated: '%s'\n",
			                alias_addr->address->address);
			goto append;
		}

		if (*val == '|') {
			DEBUG(5) debugf("alias: '%s' is a pipe address\n", val);
			alias_addr = create_recipient_pipe(val);
			DEBUG(6) debugf("alias:     pipe generated: %s\n",
			                alias_addr->address->local_part);
			goto append;
		}

		alias_addr = create_recipient(val, conf.host_name);
		if (!alias_addr) {
			logwrite(LOG_ERR, "alias '%s' expands to invalid address '%s': %s\n",
			         addr->address->address, val, parse_error);
			ok = FALSE;
			continue;
		}

		if (addr_isequal_parent(addr, alias_addr->address, conf.localpartcmp)) {
			/* loop detected, ignore this path */
			logwrite(LOG_ERR, "alias: detected loop, hence ignoring '%s'\n",
			         alias_addr->address->address);
			destroy_recipient(alias_addr);
			ok = FALSE;
			continue;
		}

		/* recurse */
		DEBUG(6) debugf("alias: >>\n");
		if (!expand_one(globalias_table, alias_table, alias_addr)) {
			DEBUG(6) debugf("alias: <<\n");
			destroy_recipient(alias_addr);
			ok = FALSE;
			continue;
		}
		DEBUG(6) debugf("alias: <<\n");

	  append:
		// this also "claims" the initial refcount of the object
		addr->children = g_list_append(addr->children, alias_addr);
		alias_addr->parent = addr;
	}
	destroy_ptr_list(val_list);

	return ok;
}

gboolean
alias_expand(const GList *globalias_table, const GList *alias_table, GList *rcpt_list)
{
	gboolean ok = TRUE;

	foreach (recipient *addr, rcpt_list) {
		if (!expand_one(globalias_table, alias_table, addr)) {
			// while the problem would be fixable, realistically it won't be
			// noticed in time. so we fail immediately rather than deferring.
			addr_mark_failed(addr);
			ok = FALSE;
		}
	}

	return ok;
}
