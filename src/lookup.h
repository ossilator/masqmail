// SPDX-FileCopyrightText: (C) Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include <glib.h>

typedef struct {
	guint32 ip;
	int pref;
	gchar *name;
} mxip_addr;


typedef GList *(*resolve_func) (const gchar *);

GList *resolve_dns_mx(const gchar *domain);
GList *resolve_byname(const gchar *domain);

void destroy_mxip_addr(mxip_addr *mxip);
void destroy_mxip_addr_list(GList *list);
