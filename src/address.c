// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

static address*
create_address_rawest(gchar *local_part, gchar *domain)
{
	address *addr = g_malloc0(sizeof(address));
	addr->local_part = local_part;
	addr->domain = domain;
	// pedantically, the local part may need quoting/escaping,
	// but our address parser doesn't dequote, either.
	addr->address = domain ? g_strdup_printf("%s@%s", local_part, domain)
	                       : g_strdup(local_part);
	return addr;
}

address*
create_address_raw(gchar *local_part, gchar *domain)
{
	return create_address_rawest(g_strdup(local_part), g_strdup(domain));
}

address*
create_address(gchar *path, addr_type_t addr_type)
{
	address *addr;
	addr = _create_address(path, NULL, addr_type);

	if (addr) {
		addr_unmark_delivered(addr);
	}
	return addr;
}

address*
create_address_qualified(gchar *path, addr_type_t addr_type, gchar *domain)
{
	address *addr = create_address(path, addr_type);

	if (addr && !addr->domain) {
		addr->domain = g_strdup(domain);
	}
	return addr;
}

/* nothing special about pipes here, but its only called for that purpose */
address*
create_address_pipe(gchar *path)
{
	address *addr = g_malloc0(sizeof(address));
	addr->address = g_strdup(path);
	addr->local_part = g_strdup(addr->address);
	addr->domain = g_strdup("localhost");  /* quick hack */
	return addr;
}

void
destroy_address(address *addr)
{
	g_free(addr->address);
	g_free(addr->local_part);
	g_free(addr->domain);
	g_free(addr);
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
		address *child = (address *) (addr_node->data);
		if (!addr_is_delivered_children(child)) {
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
		address *child = (address *) (addr_node->data);
		if (!addr_is_finished_children(child)) {
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
