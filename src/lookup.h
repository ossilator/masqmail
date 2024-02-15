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


typedef GList *(*resolve_func) (GList *, gchar *);

GList *resolve_dns_a(GList *list, gchar *domain);
GList *resolve_dns_mx(GList *list, gchar *domain);
GList *resolve_byname(GList *list, gchar *domain);
int dns_look_ip(gchar *domain, guint32 *ip);
