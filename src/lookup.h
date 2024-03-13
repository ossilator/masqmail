// SPDX-FileCopyrightText: (C) Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include <glib.h>

#define MAX_DNSNAME MAXDNAME

typedef struct {
	guint32 ip;
	int pref;
	gchar *name;
} mxip_addr;


typedef GList *(*resolve_func) (gchar *);

GList *resolve_dns_mx(gchar *domain);
GList *resolve_byname(gchar *domain);

void destroy_mxip_addr(mxip_addr *mxip);
void destroy_mxip_addr_list(GList *list);
