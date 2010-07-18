/* MasqMail Copyright (C) Oliver Kurth,
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

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "masqmail.h"


#ifdef ENABLE_RESOLVER

static union {
	HEADER hdr;
	unsigned char buf[PACKETSZ];
} response;
static unsigned char *resp_end;
static unsigned char *resp_pos;

static int num_answers;
static char name[MAX_DNSNAME];

unsigned short rr_type;
unsigned short rr_dlen;

static unsigned short
getshort(unsigned char *c)
{
	unsigned short u;
	u = c[0];
	return (u << 8) + c[1];
}

static int
dns_resolve(char *domain, int type, gboolean do_search)
{
	int n;
	int i;
	int resp_len;

	DEBUG(5) debugf("DNS: before res_search()\n");
	if (do_search)
		resp_len = res_search(domain, C_IN, type, response.buf, sizeof(response));
	else
		resp_len = res_query(domain, C_IN, type, response.buf, sizeof(response));
	DEBUG(5) debugf("DBG: after res_search()\n");

	if (resp_len <= 0) {
		/*
		   if (errno == ECONNREFUSED) return DNS_SOFT;
		   if (h_errno == TRY_AGAIN) return DNS_SOFT;
		   return DNS_HARD;
		 */
		return -1;
	}
	if (resp_len >= sizeof(response))
		resp_len = sizeof(response);

	resp_end = response.buf + resp_len;
	resp_pos = response.buf + sizeof(HEADER);
	n = ntohs(response.hdr.qdcount);

	while (n-- > 0) {
		i = dn_expand(response.buf, resp_end, resp_pos, name, MAX_DNSNAME);
		if (i < 0)
			return -1;
		DEBUG(5) debugf("DBG: resolve name = %s\n", name);
		resp_pos += i;
		i = resp_end - resp_pos;
		if (i < QFIXEDSZ)
			return -1;
		resp_pos += QFIXEDSZ;
	}
	num_answers = ntohs(response.hdr.ancount);

	return 0;
}

static int
dns_next()
{
	int i;

	if (num_answers <= 0)
		return 2;
	num_answers--;

	if (resp_pos == resp_end)
		return -1;  /* soft */

	i = dn_expand(response.buf, resp_end, resp_pos, name, 256);
	if (i < 0)
		return -1;  /* soft */
	resp_pos += i;

	i = resp_end - resp_pos;
	if (i < 4 + 3 * 2)
		return -1;  /* soft */

	rr_type = getshort(resp_pos);
	rr_dlen = getshort(resp_pos + 8);
	resp_pos += 10;

	return 0;
}

static int
dns_getip(guint32 * ip)
{
	int ret;

	if ((ret = dns_next()))
		return ret;

	if (rr_type == T_A) {
		if (rr_dlen < 4)
			return -1;  /* soft */
		*ip = *(guint32 *) (resp_pos);
		DEBUG(5) debugf("DNS: dns_getip(): ip = %s\n", inet_ntoa(*(struct in_addr *) ip));
		resp_pos += rr_dlen;

		return 1;
	}
	resp_pos += rr_dlen;
	return 0;
}

static int
dns_getmx(int *pref)
{
	int ret;

	if ((ret = dns_next()))
		return ret;

	if (rr_type == T_MX) {
		if (rr_dlen < 3)
			return -1;  /* soft */

		*pref = (resp_pos[0] << 8) + resp_pos[1];
		if (dn_expand(response.buf, resp_end, resp_pos + 2, name, MAX_DNSNAME) < 0)
			return -1;

		resp_pos += rr_dlen;

		return 1;
	}
	resp_pos += rr_dlen;
	return 0;
}

int
dns_look_ip(gchar * domain, guint32 * ip)
{
	gchar *n = domain;

	while (TRUE) {
		if (dns_resolve(n, T_A, FALSE) != 0) {
			return -1;
		}

		dns_next();
		if (rr_type == T_A) {
			if (rr_dlen < 4) {
				return -1;  /* soft */
			}
			*ip = *(guint32 *) (resp_pos);

			DEBUG(5) debugf("DNS: dns_look_ip(): ip = %s\n", inet_ntoa(*(struct in_addr *) ip));

			resp_pos += rr_dlen;
			return 0;
		} else if (rr_type == T_CNAME) {
			if (dn_expand(response.buf, resp_end, resp_pos, name, MAX_DNSNAME) < 0) {
				return -1;
			}

			DEBUG(5) debugf("DNS: (CNAME) dns_look_ip(): name = %s\n", name);

			resp_pos += rr_dlen;
			n = name;
		} else {
			return -1;
		}
	}
}

GList*
resolve_dns_a(GList * list, gchar * domain)
{
	int ret;

	DEBUG(5) debugf("DNS: resolve_dns_a entered\n");

	if (dns_resolve(domain, T_A, TRUE) == 0) {
		mxip_addr mxip;
		while ((ret = dns_getip(&(mxip.ip))) != 2) {
			if (ret == 1) {
				mxip.name = g_strdup(name);
				mxip.pref = 0;
				list = g_list_append(list, g_memdup(&mxip, sizeof(mxip)));
			}
		}
	}
	return list;
}

static gint
_mx_sort_func(gconstpointer aa, gconstpointer bb)
{
	const mxip_addr *a = (mxip_addr *) aa;
	const mxip_addr *b = (mxip_addr *) bb;

	if (a->pref == b->pref)
		return a->ip - b->ip;
	else
		return a->pref - b->pref;
}

GList*
resolve_dns_mx(GList * list, gchar * domain)
{
	GList *node;
	int ret;
	int cnt = 0;

	DEBUG(5) debugf("DNS: resolve_dns_mx entered\n");

	if (dns_resolve(domain, T_MX, TRUE) == 0) {
		GList *node_next;
		mxip_addr mxip;
		while ((ret = dns_getmx(&(mxip.pref))) != 2) {
			if (ret == 1) {
				mxip.name = g_strdup(name);
				mxip.ip = rand();
				list = g_list_append(list, g_memdup(&mxip, sizeof(mxip)));
				cnt++;
			}
		}

		DEBUG(5) debugf("DNS: found %d mx records\n", cnt);

		/* to randomize sequences with equal pref values,
		   we temporarily 'misused' the ip field and
		   put a random number in it as a secondary sort key.
		 */
		list = g_list_sort(list, _mx_sort_func);

		/* CNAME resolving has to be added as well. */

		for (node = g_list_first(list); node != NULL; node = node_next) {

			mxip_addr *p_mxip = (mxip_addr *) (node->data);
			node_next = g_list_next(node);

			if (dns_look_ip(p_mxip->name, &(p_mxip->ip)) != 0) {
				DEBUG(1) debugf("DNS: could not resolve target of mx %s\n", p_mxip->name);
				list = g_list_remove_link(list, node);
				g_free(node->data);
				g_list_free_1(node);
			}
		}
	}
	return list;
}

#endif

/* now something completely different... */

GList*
resolve_byname(GList * list, gchar * domain)
{
	struct hostent *hent;

	DEBUG(5) debugf("DNS: resolve_byname entered\n");

	if ((hent = gethostbyname(domain))) {
		char *haddr;
		int i = 0;
		while ((haddr = hent->h_addr_list[i++])) {
			mxip_addr mxip;
			mxip.ip = *(guint32 *) (haddr);
			mxip.pref = 0;
			mxip.name = g_strdup(hent->h_name);
			list = g_list_append(list, g_memdup(&mxip, sizeof(mxip)));
		}
	}
	return list;
}
