// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

address*
create_address(gchar *path, gboolean is_rfc821)
{
	address *addr;
	addr = _create_address(path, NULL, is_rfc821);

	if (addr) {
		addr_unmark_delivered(addr);
	}
	return addr;
}

address*
create_address_qualified(gchar *path, gboolean is_rfc821, gchar *domain)
{
	address *addr = create_address(path, is_rfc821);

	if (addr && !addr->domain) {
		addr->domain = g_strstrip(g_strdup(domain));
	}
	return addr;
}

/* nothing special about pipes here, but its only called for that purpose */
address*
create_address_pipe(gchar *path)
{
	address *addr = g_malloc0(sizeof(address));

	if (addr) {
		addr->address = g_strstrip(g_strdup(path));
		addr->local_part = g_strstrip(g_strdup(addr->address));
		addr->domain = g_strdup("localhost");  /* quick hack */
	}
	return addr;
}

void
destroy_address(address *addr)
{
	DEBUG(6) debugf("destroy_address entered\n");
	g_free(addr->address);
	g_free(addr->local_part);
	g_free(addr->domain);
	g_free(addr);
}

address*
copy_modify_address(const address *orig, gchar *l_part, gchar *dom)
{
	address *addr = NULL;

	if (!orig) {
		return NULL;
	}
	if (!(addr = g_malloc(sizeof(address)))) {
		return NULL;
	}
	addr->address = g_strstrip(g_strdup(orig->address));
	addr->local_part = g_strstrip(l_part ? g_strdup(l_part) :
			g_strdup(orig->local_part));
	addr->domain = g_strstrip(dom ? g_strdup(dom) :
			g_strdup(orig->domain));
	addr->flags = 0;
	addr->children = NULL;
	addr->parent = NULL;
	return addr;
}

gboolean
addr_isequal(address *addr1, address *addr2,
		int (*cmpfunc) (const char*, const char*))
{
	return (cmpfunc(addr1->local_part, addr2->local_part)==0) &&
			(strcasecmp(addr1->domain, addr2->domain)==0);
}

/* searches in ancestors of addr1 */
gboolean
addr_isequal_parent(address *addr1, address *addr2,
		int (*cmpfunc) (const char*, const char*))
{
	address *addr;

	for (addr = addr1; addr; addr = addr->parent) {
		if (addr_isequal(addr, addr2, cmpfunc)) {
			return TRUE;
		}
	}
	return FALSE;
}

/* careful, this is recursive */
/* returns TRUE if ALL children have been delivered */
gboolean
addr_is_delivered_children(address *addr)
{
	GList *addr_node;

	if (!addr->children) {
		return addr_is_delivered(addr);
	}
	foreach(addr->children, addr_node) {
		address *addr = (address *) (addr_node->data);
		if (!addr_is_delivered_children(addr)) {
			return FALSE;
		}
	}
	return TRUE;
}

/* careful, this is recursive */
/* returns TRUE if ALL children have been either delivered or have failed */
gboolean
addr_is_finished_children(address *addr)
{
	GList *addr_node;

	if (!addr->children) {
		return (addr_is_failed(addr) || addr_is_delivered(addr));
	}
	foreach(addr->children, addr_node) {
		address *addr = (address *) (addr_node->data);
		if (!addr_is_finished_children(addr)) {
			return FALSE;
		}
	}
	return TRUE;
}

/* find original address */
address*
addr_find_ancestor(address *addr)
{
	while (addr->parent) {
		addr = addr->parent;
	}
	return addr;
}

gchar*
addr_string(address *addr)
{
	static gchar *buffer = NULL;

	if (buffer) {
		g_free(buffer);
	}
	if (!addr) {
		return NULL;
	}
	if (!*addr->local_part) {
		buffer = g_strdup("<>");
	} else {
		buffer = g_strdup_printf("<%s@%s>",
				addr->local_part ? addr->local_part : "",
				addr->domain ? addr->domain : "");
	}
	return buffer;
}
