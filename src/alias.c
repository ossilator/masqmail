/*  MasqMail
    Copyright (C) 2000-2001 Oliver Kurth
    Copyright (C) 2010 markus schnalke <meillo@marmaro.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "masqmail.h"
#include <fnmatch.h>

gboolean
addr_is_local(address * addr)
{
	GList *dom_node;
	GList *addr_node;
	address *a;

	if (addr->domain == NULL) {
		return TRUE;
	}
	foreach(conf.local_hosts, dom_node) {
		/* Note: FNM_CASEFOLD is a GNU extension */
		if (fnmatch(dom_node->data, addr->domain, FNM_CASEFOLD) != 0) {
			/* no match, try next */
			continue;
		}
		foreach(conf.not_local_addresses, addr_node) {
			a = create_address_qualified(addr_node->data, TRUE, conf.host_name);
			DEBUG(6) debugf("not_local_addresses: addr_node->data=%s a->address=%s\n",
			                addr_node->data, a->address);
			if (addr_isequal(a, addr)) {
				destroy_address(a);
				/* in local_hosts but also in not_local_addresses */
				return FALSE;
			}
			destroy_address(a);
		}
		/* in local_hosts */
		return TRUE;
	}
	foreach(conf.local_addresses, addr_node) {
		a = create_address_qualified(addr_node->data, TRUE, conf.host_name);
		DEBUG(6) debugf("local_addresses: addr_node->data=%s a->address=%s\n",
		                addr_node->data, a->address);
		if (addr_isequal(a, addr)) {
			destroy_address(a);
			/* in local_addresses */
			return TRUE;
		}
		destroy_address(a);
	}
	return FALSE;
}

static gboolean
addr_isequal_alias(address * addr1, address * addr2)
{
	return (conf.alias_local_cmp(addr1->local_part, addr2->local_part) == 0)
	       && (strcasecmp(addr1->domain, addr2->domain) == 0);
}

static GList*
parse_list(gchar * line)
{
	GList *list = NULL;
	gchar buf[256];
	gchar *p, *q;

	p = line;
	while (*p != '\0') {
		q = buf;
		while (isspace(*p))
			p++;
		if (*p != '"') {
			while (*p && (*p != ',') && (q < buf + 255))
				*(q++) = *(p++);
			*q = '\0';
		} else {
			gboolean escape = FALSE;
			p++;
			while (*p && (*p != '"' || escape) && (q < buf + 255)) {
				if ((*p == '\\') && !escape)
					escape = TRUE;
				else {
					escape = FALSE;
					*(q++) = *p;
				}
				p++;
			}
			*q = '\0';
			while (*p && (*p != ','))
				p++;
		}
		list = g_list_append(list, g_strdup(g_strchomp(buf)));
		if (*p)
			p++;
	}
	return list;
}

/*
addr is assumed to be local and no pipe address nor not-to-expand
*/
static GList*
expand_one(GList* alias_table, address* addr)
{
	GList *val_list;
	GList *val_node;
	GList *alias_list = NULL;
	GList *alias_node;
	gchar *val;
	address* alias_addr;

	/* expand the local alias */
	DEBUG(6) debugf("alias: '%s' is local and will get expanded\n", addr->local_part);

	if (strcasecmp(addr->local_part, "postmaster") == 0) {
		/* postmaster must always be matched caseless
		   see RFC 822 and RFC 5321 */
		val = (gchar *) table_find_func(alias_table, addr->local_part, strcasecmp);
	} else {
		val = (gchar *) table_find_func(alias_table, addr->local_part, conf.alias_local_cmp);
	}
	if (!val) {
		DEBUG(5) debugf("alias: '%s' is fully expanded, hence completed\n",
		                addr->local_part);
		return g_list_append(NULL, addr);
	}

	DEBUG(5) debugf("alias: '%s' -> '%s'\n", addr->local_part, val);
	val_list = parse_list(val);
	alias_list = NULL;

	foreach(val_list, val_node) {
		gchar *val = (gchar *) (val_node->data);
		address *alias_addr;
		address *addr_parent = NULL;
	
		DEBUG(6) debugf("alias: processing '%s'\n", val);

		if (val[0] == '\\') {
			DEBUG(5) debugf("alias: '%s' is marked as final, hence completed\n", val);
			alias_addr = create_address_qualified(val+1, TRUE, conf.host_name);
			g_free(val);
			DEBUG(6) debugf("alias:     address generated: '%s'\n",
			                alias_addr->local_part);
			alias_list = g_list_append(alias_list, alias_addr);
			continue;
		}
	
		if (val[0] == '|') {
			DEBUG(5) debugf("alias: '%s' is a pipe address\n", val);
			alias_addr = create_address_pipe(val+1);
			g_free(val);
			DEBUG(6) debugf("alias:     pipe generated: %s\n",
			                alias_addr->local_part);
			alias_list = g_list_append(alias_list, alias_addr);
			continue;
		}

		alias_addr = create_address_qualified(val, TRUE, conf.host_name);
		g_free(val);

		if (!addr_is_local(alias_addr)) {
			DEBUG(5) debugf("alias: '%s@%s' is non-local, hence completed\n",
					alias_addr->local_part, alias_addr->domain);
			alias_list = g_list_append(alias_list, alias_addr);
			continue;
		}

		/* addr is local, so let's go into recursion and expand again,
		   but first ...  search in parents for loops: */
		for (addr_parent=addr; addr_parent; addr_parent=addr_parent->parent) {
			if (addr_isequal_alias(alias_addr, addr_parent)) {
				break;
			}
		}
		if (addr_parent) {
			/* loop detected, ignore this path */
			logwrite(LOG_ALERT,
			         "alias: detected loop (%s -> %s), hence ignoring\n",
			         addr_parent->local_part, addr->local_part);
			continue;
		}
		alias_addr->parent = addr;

		/* recurse */
		DEBUG(6) debugf("alias: >>\n");
		alias_node = expand_one(alias_table, alias_addr);
		DEBUG(6) debugf("alias: <<\n");
		if (alias_node) {
			alias_list = g_list_concat(alias_list, alias_node);
		}
	}
	g_list_free(val_list);
	addr->children = g_list_copy(alias_list);

	return alias_list;
}

GList*
alias_expand(GList* alias_table, GList* rcpt_list, GList* non_rcpt_list)
{
	GList *rcpt_node = NULL;
	GList *alias_list = NULL;
	GList *done_list = NULL;
	GList *rcpt_node_next = NULL;
	address *addr = NULL;

	for (rcpt_node=g_list_copy(rcpt_list);
	     rcpt_node;
	     rcpt_node=g_list_next(rcpt_node)) {

		addr = (address *) (rcpt_node->data);
		if (addr_is_local(addr)) {
			DEBUG(5) debugf("alias: (orig rcpt addr) expand local '%s'\n",
			                addr->local_part);
			alias_list = expand_one(alias_table, addr);
			if (alias_list) {
				done_list = g_list_concat(done_list, alias_list);
			}
		} else {
			DEBUG(5) debugf("alias: (orig rcpt addr) don't expand non-local '%s@%s'\n",
					addr->local_part, addr->domain);
			done_list = g_list_append(done_list, addr);
		}
	}

	/* we're done if we don't have to remove rcpts */
	if (!non_rcpt_list) {
		return done_list;
	}

	/* delete addresses of non_rcpt_list from done_list */
	for (rcpt_node = g_list_first(done_list); rcpt_node; rcpt_node = rcpt_node_next) {
		address *addr = (address *) (rcpt_node->data);
		GList *non_node;

		rcpt_node_next = g_list_next(rcpt_node);
		foreach(non_rcpt_list, non_node) {
			address *non_addr = (address *) (non_node->data);
			if (addr_isequal(addr, non_addr)) {
				done_list = g_list_remove_link(done_list, rcpt_node);
				g_list_free_1(rcpt_node);
				/* this address is still in the children lists
				   of the original address, simply mark them delivered */
				addr_mark_delivered(addr);
				break;
			}
		}
	}
	return done_list;
}
