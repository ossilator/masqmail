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

static gboolean
is_non_recipient(recipient *addr, GList *non_rcpt_list)
{
	GList *non_node;
	foreach (non_rcpt_list, non_node) {
		recipient *non_addr = non_node->data;
		if (addr_isequal(addr->address, non_addr->address, conf.localpartcmp)) {
			return TRUE;
		}
	}
	return FALSE;
}

/*
**  addr is assumed to be local and no pipe address nor not-to-expand
*/
static GList*
expand_one(GList *alias_table, recipient *addr, int doglob,
           GList *non_rcpt_list)
{
	GList *val_list;
	GList *val_node;
	GList *alias_list = NULL;
	GList *alias_node;
	char *addrstr;

	addrstr = doglob ? addr->address->address : addr->address->local_part;

	/* expand the local alias */
	DEBUG(6) debugf("alias: '%s' is local and will get expanded\n",
			addrstr);

	gchar *repl;
	if (conf.localpartcmp == strcasecmp ||
	    // postmaster must always be matched caselessly, see RFCs 5321 and 5322
	    strcasecmp(addr->address->local_part, "postmaster") == 0) {
		if (doglob) {
			repl = table_find_fnmatch_casefold(alias_table, addrstr);
		} else {
			repl = table_find_casefold(alias_table, addrstr);
		}
	} else {
		if (doglob) {
			// FIXME: the domain is matched case-sensitively as well
			repl = table_find_fnmatch(alias_table, addrstr);
		} else {
			repl = table_find(alias_table, addrstr);
		}
	}
	if (!repl) {
		DEBUG(5) debugf("alias: '%s' is fully expanded, hence "
				"completed\n", addrstr);
		if (!is_non_recipient(addr, non_rcpt_list)) {
			return g_list_append(NULL, addr);
		}
		return NULL;
	}

	DEBUG(5) debugf("alias: '%s' -> '%s'\n", addrstr, repl);
	val_list = parse_list(repl);
	alias_list = NULL;

	foreach(val_list, val_node) {
		gchar *val = val_node->data;
		recipient *alias_addr;
	
		DEBUG(6) debugf("alias: processing '%s'\n", val);

		if (*val == '\\') {
			DEBUG(5) debugf("alias: '%s' is marked as final, "
					"hence completed\n", val);
			alias_addr = create_recipient(val + 1, conf.host_name);
			DEBUG(6) debugf("alias:     address generated: '%s'\n",
			                alias_addr->address->address);
			goto append;
		}
	
		if (*val == '|') {
			DEBUG(5) debugf("alias: '%s' is a pipe address\n",
					val);
			alias_addr = create_recipient_pipe(g_strchomp(val));
			DEBUG(6) debugf("alias:     pipe generated: %s\n",
			                alias_addr->address->local_part);
			goto append;
		}

		alias_addr = create_recipient(val, conf.host_name);
		if (!addr_is_local(alias_addr->address)) {
			DEBUG(5) debugf("alias: '%s' is non-local, "
					"hence completed\n",
					alias_addr->address->address);
			goto append;
		}

		/* addr is local and to expand at this point */
		/* but first ... search in parents for loops: */
		if (addr_isequal_parent(addr, alias_addr->address, conf.localpartcmp)) {
			/* loop detected, ignore this path */
			logwrite(LOG_ERR, "alias: detected loop, hence ignoring '%s'\n",
			         alias_addr->address->address);
			continue;
		}

		/* recurse */
		DEBUG(6) debugf("alias: >>\n");
		alias_node = expand_one(alias_table, alias_addr, doglob, non_rcpt_list);
		DEBUG(6) debugf("alias: <<\n");
		if (alias_node) {
			alias_list = g_list_concat(alias_list, alias_node);
		}
		goto xlink;

	  append:
		if (!is_non_recipient(alias_addr, non_rcpt_list)) {
			alias_list = g_list_append(alias_list, alias_addr);
		}
	  xlink:
		addr->children = g_list_append(addr->children, alias_addr);
		alias_addr->parent = addr;
	}
	g_list_free_full(val_list, (GDestroyNotify) g_free);

	return alias_list;
}

GList*
alias_expand(GList *alias_table, GList *rcpt_list, GList *non_rcpt_list,
		int doglob)
{
	GList *rcpt_node = NULL;
	GList *alias_list = NULL;
	GList *done_list = NULL;

	for (rcpt_node = rcpt_list; rcpt_node;
			rcpt_node=g_list_next(rcpt_node)) {
		recipient *addr = rcpt_node->data;
		if (addr_is_local(addr->address)) {
			DEBUG(5) debugf("alias: expand local '%s' "
					"(orig rcpt addr)\n", addr->address->address);
			alias_list = expand_one(alias_table, addr, doglob, non_rcpt_list);
			if (alias_list) {
				done_list = g_list_concat(done_list,
						alias_list);
			}
		} else {
			DEBUG(5) debugf("alias: don't expand non-local '%s' "
					"(orig rcpt addr)\n", addr->address->address);
			done_list = g_list_append(done_list, addr);
		}
	}

	return done_list;
}
