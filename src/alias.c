/*  MasqMail
    Copyright (C) 2000-2001 Oliver Kurth

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

	foreach(conf.local_hosts, dom_node) {
		if (addr->domain == NULL)
			return TRUE;
		if (fnmatch(dom_node->data, addr->domain, FNM_CASEFOLD) == 0) {
			foreach(conf.not_local_addresses, addr_node) {
				a = create_address_qualified(addr_node->data, TRUE, conf.host_name);
				if (addr_isequal(a, addr)) {
					destroy_address(a);
					return FALSE;
				}
				destroy_address(a);
			}
			return TRUE;
		}
	}
	foreach(conf.local_addresses, addr_node) {
		a = create_address_qualified(addr_node->data, TRUE, conf.host_name);
		if (addr_isequal(a, addr)) {
			destroy_address(a);
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
	while (*p != 0) {
		q = buf;
		while (isspace(*p))
			p++;
		if (*p != '\"') {
			while (*p && (*p != ',') && (q < buf + 255))
				*(q++) = *(p++);
			*q = 0;
		} else {
			gboolean escape = FALSE;
			p++;
			while (*p && (*p != '\"' || escape) && (q < buf + 255)) {
				if ((*p == '\\') && !escape)
					escape = TRUE;
				else {
					escape = FALSE;
					*(q++) = *p;
				}
				p++;
			}
			*q = 0;
			while (*p && (*p != ','))
				p++;
		}
		list = g_list_append(list, g_strdup(g_strchomp(buf)));
		if (*p)
			p++;
	}
	return list;
}

GList*
alias_expand(GList * alias_table, GList * rcpt_list, GList * non_rcpt_list)
{
	GList *done_list = NULL;
	GList *rcpt_node = g_list_copy(rcpt_list);

	while (rcpt_node != NULL) {
		address *addr = (address *) (rcpt_node->data);
		DEBUG(5) debugf("alias_expand begin: '%s@%s'\n", addr->local_part, addr->domain);
		/* if(addr_is_local(addr) && (addr->local_part[0] != '|') && */
		if (addr_is_local(addr) && !(addr->flags & ADDR_FLAG_NOEXPAND)) {
			gchar *val;

			/* special handling for postmaster */
			if (strcasecmp(addr->local_part, "postmaster") == 0)
				val = (gchar *) table_find_func(alias_table, addr->local_part, strcasecmp);
			else
				val = (gchar *) table_find_func(alias_table, addr->local_part, conf.alias_local_cmp);

			DEBUG(5) debugf("alias: '%s' is local\n", addr->local_part);
			if (val != NULL) {
				GList *val_list = parse_list(val);
				GList *val_node;
				GList *alias_list = NULL;

				DEBUG(5) debugf("alias: '%s' -> '%s'\n", addr->local_part, val);
				foreach(val_list, val_node) {
					gchar *val = (gchar *) (val_node->data);
					address *alias_addr;
					address *addr_parent = NULL;

					if (val[0] == '|') {
						DEBUG(5) debugf("alias: %s is a pipe address\n", val);
						alias_addr = create_address_pipe(val);
						DEBUG(5) debugf("alias_pipe: %s is a pipe address\n", alias_addr->local_part);
					} else if (val[0] == '\\') {
						DEBUG(5) debugf("alias: shall not be expanded: '%s'\n", val);
						alias_addr = create_address_qualified(&(val[1]), TRUE, conf.host_name);
						alias_addr->flags |= ADDR_FLAG_NOEXPAND;
						DEBUG(5) debugf("alias: not expanded: '%s'\n", alias_addr->local_part);
					} else {
						alias_addr = create_address_qualified(val, TRUE, conf.host_name);

						/* search in parents for loops: */
						for (addr_parent = addr; addr_parent; addr_parent = addr_parent->parent) {
							if (addr_isequal_alias (alias_addr, addr_parent)) {
								logwrite(LOG_ALERT,
								         "detected alias loop, (ignoring): %s@%s -> %s@%s\n",
								         addr_parent->local_part,
								         addr_parent->domain,
								         addr->local_part, addr->domain);
								break;
							}
						}
					}
					if (!addr_parent) {
						alias_list = g_list_append(alias_list, alias_addr);
						alias_addr->parent = addr;
					}
					g_free(val);
				}
				g_list_free(val_list);
				addr->children = g_list_copy(alias_list);
				rcpt_node = g_list_concat(rcpt_node, alias_list);
			} else {
				DEBUG(5) debugf("alias: '%s' is completed\n", addr->local_part);
				done_list = g_list_append(done_list, addr);
			}
		} else {
			DEBUG(5) debugf("alias: '%s@%s' is not local\n", addr->local_part, addr->domain);
			done_list = g_list_append(done_list, addr);
		}
		rcpt_node = g_list_next(rcpt_node);
	}

	/* delete addresses from done_list if they are in the non_rcpt_list */
	if (non_rcpt_list) {
		GList *rcpt_node_next;
		for (rcpt_node = g_list_first(done_list); rcpt_node; rcpt_node = rcpt_node_next) {
			address *addr = (address *) (rcpt_node->data);
			GList *non_node;

			rcpt_node_next = g_list_next(rcpt_node);

			foreach(non_rcpt_list, non_node) {
				address *non_addr = (address *) (non_node->data);
				if (addr_isequal(addr, non_addr)) {
					done_list = g_list_remove_link(done_list, rcpt_node);
					g_list_free_1(rcpt_node);
					addr_mark_delivered(addr);  /* this address is still in the children lists of the original address */
					break;
				}
			}
		}
	}
	return done_list;
}
