// SPDX-FileCopyrightText: (C) 2000-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <fnmatch.h>

gboolean
addr_is_local(address *addr)
{
	GList *dom_node;
	GList *addr_node;
	address *a;

	if (!addr->domain[0]) {
		return TRUE;
	}
	foreach(conf.local_hosts, dom_node) {
		/* Note: FNM_CASEFOLD is a GNU extension */
		if (fnmatch(dom_node->data, addr->domain, FNM_CASEFOLD)!=0) {
			/* no match, try next */
			continue;
		}
		foreach(conf.not_local_addresses, addr_node) {
			a = create_address(addr_node->data, A_RFC821, conf.host_name);
			DEBUG(6) debugf("not_local_addresses: "
					"addr_node->data=%s a->address=%s\n",
			                addr_node->data, a->address);
			if (addr_isequal(a, addr, conf.localpartcmp)) {
				/* also in not_local_addresses */
				destroy_address(a);
				return FALSE;
			}
			destroy_address(a);
		}
		/* in local_hosts */
		return TRUE;
	}
	foreach(conf.local_addresses, addr_node) {
		a = create_address(addr_node->data, A_RFC821, conf.host_name);
		DEBUG(6) debugf("local_addresses: addr_node->data=%s "
				"a->address=%s\n",
		                addr_node->data, a->address);
		if (addr_isequal(a, addr, conf.localpartcmp)) {
			/* in local_addresses */
			destroy_address(a);
			return TRUE;
		}
		destroy_address(a);
	}
	return FALSE;
}

static GList*
parse_list(gchar *line)
{
	GList *list = NULL;
	gchar buf[256];
	gchar *p, *q;

	p = line;
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

static void
expand_one(GList *globalias_table, GList *alias_table, recipient *addr)
{
	GList *val_list;
	GList *val_node;

	if (!addr_is_local(addr->address)) {
		DEBUG(5) debugf("alias: '%s' is non-local, hence completed\n",
		                addr->address->address);
		return;
	}

	/* expand the local alias */
	DEBUG(6) debugf("alias: '%s' is local and will get expanded\n",
	                addr->address->address);

	gchar *repl;
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
		return;
	}

	DEBUG(5) debugf("alias: '%s' -> '%s'\n", addr->address->address, repl);
	addr_mark_alias(addr);

	val_list = parse_list(repl);
	foreach(val_list, val_node) {
		gchar *val = val_node->data;
		recipient *alias_addr;
	
		DEBUG(6) debugf("alias: processing '%s'\n", val);

		if (*val == '\\') {
			DEBUG(5) debugf("alias: '%s' is marked as final, "
					"hence completed\n", val);
			alias_addr = create_recipient(val + 1, conf.host_name);
			if (!alias_addr) {
				logwrite(LOG_ERR, "alias '%s' expands to invalid address '%s': %s\n",
				         addr->address->address, val + 1, parse_error);
				continue;
			}
			DEBUG(6) debugf("alias:     address generated: '%s'\n",
			                alias_addr->address->address);
			goto append;
		}
	
		if (*val == '|') {
			DEBUG(5) debugf("alias: '%s' is a pipe address\n",
					val);
			alias_addr = create_recipient_pipe(val);
			DEBUG(6) debugf("alias:     pipe generated: %s\n",
			                alias_addr->address->local_part);
			goto append;
		}

		alias_addr = create_recipient(val, conf.host_name);
		if (!alias_addr) {
			logwrite(LOG_ERR, "alias '%s' expands to invalid address '%s': %s\n",
			         addr->address->address, val, parse_error);
			continue;
		}

		if (addr_isequal_parent(addr, alias_addr->address, conf.localpartcmp)) {
			/* loop detected, ignore this path */
			logwrite(LOG_ERR, "alias: detected loop, hence ignoring '%s'\n",
			         alias_addr->address->address);
			continue;
		}

		/* recurse */
		DEBUG(6) debugf("alias: >>\n");
		expand_one(globalias_table, alias_table, alias_addr);
		DEBUG(6) debugf("alias: <<\n");

	  append:
		addr->children = g_list_append(addr->children, alias_addr);
		alias_addr->parent = addr;
	}
	destroy_ptr_list(val_list);
}

void
alias_expand(GList *globalias_table, GList *alias_table, GList *rcpt_list)
{
	GList *rcpt_node = NULL;

	for (rcpt_node = rcpt_list; rcpt_node;
			rcpt_node=g_list_next(rcpt_node)) {
		recipient *addr = rcpt_node->data;
		expand_one(globalias_table, alias_table, addr);
	}
}
