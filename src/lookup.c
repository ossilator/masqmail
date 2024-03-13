// SPDX-FileCopyrightText: (C) Oliver Kurth
// SPDX-FileCopyrightText: (C) markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <netdb.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef ENABLE_RESOLVER

static int
dns_resolve(char *domain, int type, gboolean do_search,
            guchar *nsbuf, ns_msg *nsmsg)
{
	int resp_len;

	DEBUG(5) debugf("DNS: before res_search()\n");
	if (do_search)
		resp_len = res_search(domain, ns_c_in, type, nsbuf, NS_MAXMSG);
	else
		resp_len = res_query(domain, ns_c_in, type, nsbuf, NS_MAXMSG);
	DEBUG(5) debugf("DBG: after res_search()\n");

	if (resp_len <= 0) {
		/*
		**  if (errno == ECONNREFUSED) return DNS_SOFT;
		**  if (h_errno == TRY_AGAIN) return DNS_SOFT;
		**  return DNS_HARD;
		*/
		return -1;
	}

	// set it centrally for the case we find corrupted data
	h_errno = NETDB_INTERNAL;
	errno = EMSGSIZE;  // libresolv uses that for parsing errors

	return ns_initparse(nsbuf, resp_len, nsmsg);
}

static GList*
resolve_dns_a(GList *list, gchar *domain, gboolean do_search, int pref)
{
	ns_rr rr;
	ns_msg nsmsg;
	guchar nsbuf[NS_MAXMSG];

	DEBUG(5) debugf("DNS: resolve_dns_a entered\n");

	if (dns_resolve(domain, ns_t_a, do_search, nsbuf, &nsmsg) == 0) {
		mxip_addr mxip;
		for (int i = 0; i < ns_msg_count(nsmsg, ns_s_an); i++) {
			if (ns_parserr(&nsmsg, ns_s_an, i, &rr) < 0)
				goto afail;
			if (ns_rr_type(rr) == ns_t_a) {
				if (ns_rr_rdlen(rr) != 4)
					goto afail;
				mxip.name = g_strdup(ns_rr_name(rr));
				mxip.ip = htonl(ns_get32(ns_rr_rdata(rr)));
				mxip.pref = pref;
				list = g_list_append(list, g_memdup2(&mxip, sizeof(mxip)));
			}
		}
	}
	return list;

  afail:
	destroy_mxip_addr_list(list);
	return NULL;
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
resolve_dns_mx(gchar *domain)
{
	GList *list = NULL;
	GList *node;
	int cnt = 0;
	ns_rr rr;
	ns_msg nsmsg;
	gchar dname[NS_MAXDNAME];
	guchar nsbuf[NS_MAXMSG];

	DEBUG(5) debugf("DNS: resolve_dns_mx entered\n");

	if (dns_resolve(domain, ns_t_mx, TRUE, nsbuf, &nsmsg) == 0) {
		mxip_addr mxip;
		GList *tmp_list = NULL;
		for (int i = 0; i < ns_msg_count(nsmsg, ns_s_an); i++) {
			if (ns_parserr(&nsmsg, ns_s_an, i, &rr) < 0)
				goto mxfail;
			if (ns_rr_type(rr) == ns_t_mx) {
				if (ns_rr_rdlen(rr) < 3)
					break;
				if (dn_expand(ns_msg_base(nsmsg), ns_msg_end(nsmsg),
				              ns_rr_rdata(rr) + 2, dname, NS_MAXDNAME) < 0)
					goto mxfail;
				mxip.name = g_strdup(dname);
				mxip.ip = rand();
				mxip.pref = ns_get16(ns_rr_rdata(rr));
				tmp_list = g_list_append(tmp_list, g_memdup2(&mxip, sizeof(mxip)));
				cnt++;
			}
		}

		DEBUG(5) debugf("DNS: found %d mx records\n", cnt);

		/*
		**  to randomize sequences with equal pref values,
		**  we temporarily 'misused' the ip field and
		**  put a random number in it as a secondary sort key.
		*/
		tmp_list = g_list_sort(tmp_list, _mx_sort_func);

		foreach (tmp_list, node) {
			mxip_addr *p_mxip = (mxip_addr *) (node->data);
			list = resolve_dns_a(list, p_mxip->name, FALSE, p_mxip->pref);
			if (!list)
				break;
		}

	  mxfail:
		destroy_mxip_addr_list(tmp_list);
	} else {
		list = resolve_dns_a(list, domain, TRUE, 0);
	}
	return list;
}

#endif

/* now something completely different... */

GList*
resolve_byname(gchar *domain)
{
	GList *list = NULL;
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
			list = g_list_append(list, g_memdup2(&mxip, sizeof(mxip)));
		}
	}
	return list;
}

void
destroy_mxip_addr(mxip_addr *mxip)
{
	g_free(mxip->name);
	g_free(mxip);
}

void
destroy_mxip_addr_list(GList *list)
{
	g_list_free_full(list, (GDestroyNotify) destroy_mxip_addr);
}
