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
#include <fnmatch.h>

connect_route *find_route(GList *route_list, gchar *name)
{
  GList *route_node;
  connect_route *route = NULL;
  
  foreach(route_list, route_node){
    route = (connect_route *)(route_node->data);
    
    if(strcmp(name, route->name) == 0)
      return route;
  }
  return NULL;
}

msgout_perhost *create_msgout_perhost(gchar *host)
{
  msgout_perhost *mo_ph = g_malloc(sizeof(msgout_perhost));
  if(mo_ph){
    mo_ph->host = g_strdup(host);
    mo_ph->msgout_list = NULL;
  }
  return mo_ph;
}

void destroy_msgout_perhost(msgout_perhost *mo_ph)
{
  GList *mo_node;

  foreach(mo_ph->msgout_list, mo_node){
    msg_out *mo = (msg_out *)(mo_node->data);
    /* the rcpt_list is owned by the msgout's,
       but not the rcpt's themselves */
    g_list_free(mo->rcpt_list);
    g_free(mo);
  }
  g_list_free(mo_ph->msgout_list);
  g_free(mo_ph);
}

void rewrite_headers(msg_out *msgout, connect_route *route)
{
  /* if set_h_from_domain is set, replace domain in all
     From: headers.
  */
  msgout->hdr_list = g_list_copy(msgout->msg->hdr_list);

  /* map from addresses */
  if(route->map_h_from_addresses != NULL){
    GList *hdr_node;
    foreach(msgout->hdr_list, hdr_node){
      header *hdr = (header *)(hdr_node->data);
      if(hdr->id == HEAD_FROM){
	header *new_hdr = copy_header(hdr);
	if(map_address_header(new_hdr, route->map_h_from_addresses)){
	  hdr_node->data = new_hdr;
	  /* we need this list only to carefully free the extra headers: */
	  msgout->xtra_hdr_list =
	    g_list_append(msgout->xtra_hdr_list, new_hdr);
	}else
	  g_free(new_hdr);
      }
    }
  }

  /* replace from domain */
  if(route->set_h_from_domain != NULL){
    GList *hdr_node;

    foreach(msgout->hdr_list, hdr_node){
      header *hdr = (header *)(hdr_node->data);
      if(hdr->id == HEAD_FROM){
	header *new_hdr = copy_header(hdr);

	DEBUG(5) debugf("setting From: domain to %s\n",
			route->set_h_from_domain);
	set_address_header_domain(new_hdr, route->set_h_from_domain);
	hdr_node->data = new_hdr;
	/* we need this list only to carefully free the extra headers: */
	DEBUG(6) debugf("header = %s\n",
			new_hdr->header);
	msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
      }
    }
  }

  /* map reply-to addresses */
  if(route->map_h_reply_to_addresses != NULL){
    GList *hdr_node;
    foreach(msgout->hdr_list, hdr_node){
      header *hdr = (header *)(hdr_node->data);
      if(hdr->id == HEAD_REPLY_TO){
	header *new_hdr = copy_header(hdr);
	if(map_address_header(new_hdr, route->map_h_reply_to_addresses)){
	  hdr_node->data = new_hdr;
	  /* we need this list only to carefully free the extra headers: */
	  msgout->xtra_hdr_list =
	    g_list_append(msgout->xtra_hdr_list, new_hdr);
	}else
	  g_free(new_hdr);
      }
    }
  }

  /* replace Reply-to domain */
  if(route->set_h_reply_to_domain != NULL){
    GList *hdr_node;

    foreach(msgout->hdr_list, hdr_node){
      header *hdr = (header *)(hdr_node->data);
      if(hdr->id == HEAD_REPLY_TO){
	header *new_hdr = copy_header(hdr);

	set_address_header_domain(new_hdr, route->set_h_reply_to_domain);
	hdr_node->data = new_hdr;
	/* we need this list only to carefully free the extra headers: */
	msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
      }
    }
  }

  /* set Sender: domain to return_path->domain */
  if(route->expand_h_sender_domain){
    GList *hdr_node;

    foreach(msgout->hdr_list, hdr_node){
      header *hdr = (header *)(hdr_node->data);
      if(hdr->id == HEAD_SENDER){
	header *new_hdr = copy_header(hdr);

	set_address_header_domain(new_hdr, msgout->return_path->domain);
	hdr_node->data = new_hdr;
	/* we need this list only to carefully free the extra headers: */
	msgout->xtra_hdr_list = g_list_append(msgout->xtra_hdr_list, new_hdr);
      }
    }
  }

  if(msgout->xtra_hdr_list == NULL){
    /* nothing was changed */
    g_list_free(msgout->hdr_list);
    msgout->hdr_list = NULL;
  }
  DEBUG(5) debugf("rewrite_headers() returning\n");
}

GList *rcptlist_with_one_of_hostlist(GList *rcpt_list, GList *host_list,
				     gboolean do_include)
{
  GList *rcpt_node;
  GList *extr_list = NULL;
  GList *rcpt_node_next;

  if(rcpt_list == NULL)
    return NULL;

  /* an empty host_list matches all for an inclusive list,
     none for an exclusive list */
  if(host_list == NULL)
    return rcpt_list;

  foreach(rcpt_list, rcpt_node){
    address *adr = (address *)(rcpt_node->data);
    GList *host_node;

    for(host_node = g_list_first(host_list);
	host_node;
	host_node = g_list_next(host_node)){

      gchar *host = (gchar *)(host_node->data);
      
      if(fnmatch(host, adr->domain, FNM_CASEFOLD) == 0)
	break;
    }

    if((host_node && do_include) ||  /* if found and we want an
					'included' list */
       !(host_node || do_include)){  /* or if not found and we want an
				       'excl' list */
      extr_list = g_list_append(extr_list, adr);
    }
  }
  g_list_free(rcpt_list);

  return extr_list;
}

static gint _g_list_strcmp(gconstpointer a, gconstpointer b)
{
  return (gint)strcmp(a, b);
}

gboolean route_is_allowed_mail_local(connect_route *route, address *ret_path)
{
  gchar *loc_part = ret_path->local_part;

  if(route->not_allowed_mail_locals != NULL){
    if(g_list_find_custom(route->not_allowed_mail_locals, loc_part,
			 _g_list_strcmp) != NULL)
      return FALSE;
  }
  if(route->allowed_mail_locals != NULL){
    if(g_list_find_custom(route->allowed_mail_locals, loc_part,
			  _g_list_strcmp) != NULL)
      return TRUE;
    else
      return FALSE;
  }
  return TRUE;
}

GList *msg_rcptlist_route(connect_route *route, GList *rcpt_list)
{
  rcpt_list =
    rcptlist_with_one_of_hostlist(rcpt_list,
				  conf.local_hosts, FALSE);
  rcpt_list =
    rcptlist_with_one_of_hostlist(rcpt_list,
				  conf.local_nets, route->is_local_net);
  /* sort out those domains that can be sent over this connection: */
  rcpt_list =
    rcptlist_with_one_of_hostlist(rcpt_list,
				  route->allowed_rcpt_domains, TRUE);
  /* sort out those domains that cannot be sent over this connection: */
  rcpt_list =
    rcptlist_with_one_of_hostlist(rcpt_list,
				  route->not_allowed_rcpt_domains, FALSE);
  return rcpt_list;
}

/* check whether msg is valid for this route and
   leave only valid recipients in msgout
*/
gboolean route_strip_msgout(connect_route *route, msg_out *msgout)
{
  message *msg = msgout->msg;
  GList *rcpt_list = msgout->rcpt_list;
  if(rcpt_list == NULL)
    rcpt_list = g_list_copy(msg->rcpt_list);

  if(!route_is_allowed_mail_local(route, msg->return_path)){
    logwrite(LOG_NOTICE, "%s == %s is not allowed to send over this route.\n",
	     msg->uid, msg->return_path->local_part);
    return FALSE;
  }
  msgout->rcpt_list = msg_rcptlist_route(route, rcpt_list);

  return (msgout->rcpt_list != NULL);
}

msg_out *route_prepare_msgout(connect_route *route, msg_out *msgout)
{
  message *msg = msgout->msg;
  GList *rcpt_list = msgout->rcpt_list;

  if(rcpt_list != NULL){
    /* found a few */
    DEBUG(5){
      GList *node;
      debugf("rcpts for routed delivery, route = %s, id = %s\n", route->name, msg->uid);
      foreach(rcpt_list, node){
	address *rcpt = (address *)(node->data);
	debugf("rcpt for ruted delivery: <%s@%s>\n",
	       rcpt->local_part, rcpt->domain);
      }
    }
      
    /* rewrite return path
       if there is a table, use that
       if an address is found and if it has a domain, use that
    */
    if(route->map_return_path_addresses){
      address *ret_path = NULL;
      DEBUG(5) debugf("looking up %s in map_return_path_addresses\n",
		      msg->return_path->local_part);
      ret_path =
	(address *)table_find(route->map_return_path_addresses,
			      msg->return_path->local_part);
      if(ret_path){
	DEBUG(5) debugf("found <%s@%s>\n",
			ret_path->local_part, ret_path->domain); 
	if(ret_path->domain == NULL)
	  ret_path->domain =
	    route->set_return_path_domain ?
	    route->set_return_path_domain : msg->return_path->domain;
	msgout->return_path = copy_address(ret_path);
      }
    }
    if(msgout->return_path == NULL){
      DEBUG(5) debugf("setting return path to %s\n",
		      route->set_return_path_domain);
      msgout->return_path =
	copy_modify_address(msg->return_path,
			    NULL, route->set_return_path_domain);
    }
    rewrite_headers(msgout, route);

    return msgout;
  }
  return NULL;
}

/* put msgout's is msgout_list into bins (msgout_perhost structs) for each
   host. Used if there is no mail_host.
   route param is not used, we leave it here because that may change.
 */

GList *route_msgout_list(connect_route *route, GList *msgout_list)
{
  GList *mo_ph_list = NULL;
  GList *msgout_node;

  foreach(msgout_list, msgout_node){
    msg_out *msgout = (msg_out *)(msgout_node->data);
    msg_out *msgout_new;
    GList *rcpt_list = msgout->rcpt_list;
    GList *rcpt_node;

    foreach(rcpt_list, rcpt_node){
      address *rcpt = rcpt_node->data;
      msgout_perhost *mo_ph = NULL;
      GList *mo_ph_node = NULL;

      /* search host in mo_ph_list */
      foreach(mo_ph_list, mo_ph_node){
	mo_ph = (msgout_perhost *)(mo_ph_node->data);
	if(strcasecmp(mo_ph->host, rcpt->domain) == 0)
	  break;
      }
      if(mo_ph_node != NULL){
	/* there is already a rcpt for this host */
	GList *msgout_node;
	msg_out *msgout_last =
	  (msg_out *)((g_list_last(mo_ph->msgout_list))->data);
	if(msgout_last->msg == msgout->msg){
	  /* if it is also the same message, it must be the last one
	     appended to mo_ph->msgout_list (since outer loop goes through
	     msgout_list) */
	  msgout_last->rcpt_list =
	    g_list_append(msgout_last->rcpt_list, rcpt);
	}else{
	  /* if not, we append a new msgout */
	  /* make a copy of msgout */
	  msgout_new = create_msg_out(msgout->msg);
	  msgout_new->return_path = msgout->return_path;
	  msgout_new->hdr_list = msgout->hdr_list;

	  /* append our rcpt to it */
	  /* It is the 1st rcpt for this msg to this host,
	     therefore we safely give NULL */
	  msgout_new->rcpt_list = g_list_append(NULL, rcpt);
	  mo_ph->msgout_list =
	    g_list_append(mo_ph->msgout_list, msgout_new);
	}
      }else{
	/* this rcpt to goes to another host */
	mo_ph = create_msgout_perhost(rcpt->domain);
	mo_ph_list = g_list_append(mo_ph_list, mo_ph);

	/* make a copy of msgout */
	msgout_new = create_msg_out(msgout->msg);
	msgout_new->return_path = msgout->return_path;
	msgout_new->hdr_list = msgout->hdr_list;
	    
	/* append our rcpt to it */
	/* It is the 1st rcpt for this msg to this host,
	   therefore we safely give NULL */
	msgout_new->rcpt_list = g_list_append(NULL, rcpt);
	mo_ph->msgout_list = g_list_append(mo_ph->msgout_list, msgout_new);
      }/* if mo_ph != NULL */
    }/* foreach(rcpt_list, ... */
  }/* foreach(msgout_list, ... */

  return mo_ph_list;
}
