/*  MasqMail
    Copyright (C) 1999 Oliver Kurth

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

static
GList *resolve_ip(GList *list, gchar *ip)
{
  struct in_addr ia;
  if(inet_aton(ip, &ia)){
    mxip_addr mxip;
    
    mxip.name = g_strdup(ip);
    mxip.pref = 0;
    mxip.ip = (guint32) *(guint32 *)(&ia);
    list = g_list_append(list, g_memdup(&mxip, sizeof(mxip)));
  }
  /* logwrite(LOG_ALERT, "invalid address '%s': inet_aton() failed\n", ip);*/
  return NULL;
}

mxip_addr *connect_hostlist(int *psockfd, gchar *host, guint port,
			  GList *addr_list)
{
  GList *addr_node;
  struct sockaddr_in saddr;

  DEBUG(5) debugf("connect_hostlist entered\n");

  for(addr_node = g_list_first(addr_list);
      addr_node;
      addr_node = g_list_next(addr_node)){
    mxip_addr *addr = (mxip_addr *)(addr_node->data);

    *psockfd = socket(PF_INET, SOCK_STREAM, 0);

    memset(&saddr, 0, sizeof(saddr));

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);

    /* clumsy, but makes compiler happy: */
    saddr.sin_addr = *(struct in_addr*)(&(addr->ip));
    DEBUG(5) debugf("trying ip %s port %d\n", inet_ntoa(saddr.sin_addr), port);
    if(connect(*psockfd, (struct sockaddr *)(&saddr), sizeof(saddr)) == 0){
      DEBUG(5) debugf("connected to %s\n", inet_ntoa(saddr.sin_addr));
      return addr;
    }else{
      int saved_errno = errno;

      close(*psockfd);

      logwrite(LOG_WARNING, "connection to %s failed: %s\n",
	       inet_ntoa(saddr.sin_addr), strerror(errno));

      errno = saved_errno;

      if((saved_errno != ECONNREFUSED) &&
	 (saved_errno != ETIMEDOUT) &&
	 (saved_errno != ENETUNREACH) &&
	 (saved_errno != EHOSTUNREACH))

	return NULL;
    }
  }
  return NULL;
}

/* Given a list of resolver functions, this function
   resolve the host and tries to connect to the addresses
   returned. If a connection attemp is timed out or refused,
   the next address is tried.

   TODO: the resolver functions might return duplicate addresses,
   if attempt failed for one it should not be tried again.
*/

mxip_addr *connect_resolvelist(int *psockfd, gchar *host, guint port,
			       GList *res_func_list)
{
  GList *res_node;
  GList *addr_list;

  DEBUG(5) debugf("connect_resolvelist entered\n");

  h_errno = 0;

  if(isdigit(host[0])){
    mxip_addr *addr;
    
    addr_list = resolve_ip(NULL, host);
    if(addr_list){
      addr = connect_hostlist(psockfd, host, port, addr_list);
      g_list_free(addr_list);
      return addr;
    }
    /* previous versions complained, until someone tried to use a hostname
       out there that begins with a digit. eg. '3dwars.de'. */
  }

  if(res_func_list == NULL){
    logwrite(LOG_ALERT, "res_funcs == NULL !!!\n");
    exit(EXIT_FAILURE);
  }

  foreach(res_func_list, res_node){
    resolve_func res_func;
    DEBUG(6) debugf("connect_resolvelist 1a\n");
    res_func = (resolve_func)(res_node->data);
      
    if(res_func == NULL){
      logwrite(LOG_ALERT, "res_func == NULL !!!\n");
      exit(EXIT_FAILURE);
    }
      
    errno = 0;
    if((addr_list = res_func(NULL, host))){
	
      mxip_addr *addr;
      if((addr = connect_hostlist(psockfd, host, port, addr_list)))
	return addr;

      DEBUG(5){
	debugf("connect_hostlist failed: %s\n", strerror(errno));
      }
	
      g_list_free(addr_list);
    }else{
      if(!g_list_next(res_node)){
	logwrite(LOG_ALERT, "could not resolve %s: %s\n", host, hstrerror(h_errno));
      }
    }
  }
  return NULL;

}

