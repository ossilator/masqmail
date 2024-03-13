// SPDX-FileCopyrightText: (C) 1999 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <assert.h>
#include <netdb.h>
#include <arpa/inet.h>

static GList*
resolve_ip(gchar *ip)
{
	struct in_addr ia;
	mxip_addr mxip;

	if (!inet_aton(ip, &ia)) {
		/* No dots-and-numbers notation. */
		return NULL;
	}
	mxip.name = g_strdup(ip);
	mxip.pref = 0;
	mxip.ip = ia.s_addr;
	return g_list_append(NULL, g_memdup2(&mxip, sizeof(mxip)));
}

static mxip_addr*
connect_hostlist(int *psockfd, gint port, GList *addr_list)
{
	GList *addr_node;
	struct sockaddr_in saddr;
	int saved_errno;

	DEBUG(5) debugf("connect_hostlist entered\n");

	for (addr_node = g_list_first(addr_list); addr_node;
			addr_node = g_list_next(addr_node)) {
		mxip_addr *addr = (mxip_addr *) (addr_node->data);
		*psockfd = socket(PF_INET, SOCK_STREAM, 0);

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		/* clumsy, but makes compiler happy: */
		saddr.sin_addr = *(struct in_addr *) (&(addr->ip));

		DEBUG(5) debugf("  trying ip %s port %d\n",
				inet_ntoa(saddr.sin_addr), port);

		if (connect(*psockfd, (struct sockaddr *) &saddr,
				sizeof(saddr))==0) {
			DEBUG(5) debugf("  connected to %s\n",
					inet_ntoa(saddr.sin_addr));
			return addr;
		}

		saved_errno = errno;
		logerrno(LOG_WARNING, "connection to %s failed",
		         inet_ntoa(saddr.sin_addr));
		close(*psockfd);
		errno = saved_errno;

		if ((saved_errno != ECONNREFUSED) &&
				(saved_errno != ETIMEDOUT) &&
				(saved_errno != ENETUNREACH) &&
				(saved_errno != EHOSTUNREACH)) {
			return NULL;
		}
	}
	return NULL;
}

/*
**  Given a list of resolver functions, this function
**  resolve the host and tries to connect to the addresses
**  returned. If a connection attemp is timed out or refused,
**  the next address is tried.
*/
mxip_addr*
connect_resolvelist(int *psockfd, gchar *host, gint port,
		GList *res_func_list, gchar **err_msg)
{
	GList *res_node;
	GList *addr_list;

	DEBUG(5) debugf("connect_resolvelist entered\n");

	if (isdigit(*host)) {
		if ((addr_list = resolve_ip(host))) {
			goto gotip;
		}
		/*
		**  Probably a hostname that begins with a digit.
		**  E.g. '3dwars.de'. Thus fall ...
		*/
	}

	assert(res_func_list);
	foreach(res_func_list, res_node) {
		resolve_func res_func;
		DEBUG(6) debugf("  foreach() body\n");

		res_func = (resolve_func) res_node->data;
		assert(res_func);

		if ((addr_list = res_func(host))) {
			goto gotip;
		}
	}
	const char *err_str = h_errno != NETDB_INTERNAL ?
	                      hstrerror(h_errno) : strerror(errno);
	logwrite(LOG_ERR, "could not resolve %s: %s\n", host, err_str);
	*err_msg = g_strdup_printf("Could not resolve host %s:\n\t%s\n",
	                           host, err_str);
	return NULL;

  gotip: ;
	mxip_addr *addr = connect_hostlist(psockfd, port, addr_list);
	if (addr) {
		addr_list = g_list_remove(addr_list, addr);
	} else {
		*err_msg = g_strdup_printf("Could not connect to %s:%ds:\n\t%s\n",
		                           host, port, strerror(errno));
	}
	destroy_mxip_addr_list(addr_list);
	return addr;
}
