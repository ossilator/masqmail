/* MasqMail
 * Copyright (C) Oliver Kurth,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define MAX_DNSNAME MAXDNAME

typedef struct {
	guint32 ip;
	int pref;
	guchar *name;
} mxip_addr;


typedef GList *(*resolve_func) (GList *, gchar *);

GList *resolve_dns_a(GList * list, gchar * domain);
GList *resolve_dns_mx(GList * list, gchar * domain);
GList *resolve_byname(GList * list, gchar * domain);
int dns_look_ip(gchar * domain, guint32 * ip);
