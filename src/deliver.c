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
#include "smtp_out.h"
#include <fnmatch.h>

gboolean deliver_local(msg_out *msgout, GList *rcpt_list)
{
  message *msg = msgout->msg;
  GList *rcpt_node;
  gboolean ok = TRUE;
  gboolean flag = FALSE;

  DEBUG(5) debugf("deliver_local entered\n");

  flag = (msg->data_list == NULL);
  if(flag){
    if(!(ok = spool_read_data(msg))){
      logwrite(LOG_ALERT, "could not open data spool file for %s\n",
	       msg->uid);
    }
  }
  if(!ok) return FALSE;

  ok = FALSE;
  for(rcpt_node = g_list_first(rcpt_list);
      rcpt_node;
      rcpt_node = g_list_next(rcpt_node)){
    GList *hdr_list;
    address *rcpt = (address *)(rcpt_node->data);
    address *env_addr = addr_find_ancestor(rcpt);
    address *ret_path = msg->return_path;
    header *retpath_hdr, *envto_hdr;

    /* here we should insert code
       for alias and .forward expansions.
       at the moment, we just check whether the recp. is
       a local user.
    */

    /* we need a private copy of the hdr list because we add headers here
       that belong to the rcpt only.
       g_list_copy copies only the nodes, so it is safe to
       g_list_free it
    */
    hdr_list = g_list_copy(msg->hdr_list);
    retpath_hdr = create_header(HEAD_ENVELOPE_TO,
				"Envelope-to: <%s@%s>\n",
				env_addr->local_part, env_addr->domain);

    envto_hdr = create_header(HEAD_RETURN_PATH,
			      "Return-path: <%s@%s>\n",
			      ret_path->local_part, ret_path->domain);
    
    hdr_list = g_list_prepend(hdr_list, envto_hdr);
    hdr_list = g_list_prepend(hdr_list, retpath_hdr);

    if(rcpt->local_part[0] == '|'){
      DEBUG(1) debugf("attempting to deliver %s with pipe\n", msg->uid);
      if(pipe_out(msg, hdr_list, rcpt->local_part)){
	logwrite(LOG_NOTICE, "%s => %s <%s@%s> with pipe\n",
		 msg->uid, rcpt->local_part,
		 env_addr->local_part, env_addr->domain
		 );
	adr_mark_delivered(rcpt);
	ok = TRUE;
      }
    }else{
      DEBUG(1) debugf("attempting to deliver %s with local\n", msg->uid);
      if(append_file(msg, hdr_list, rcpt->local_part)){
	if(env_addr != rcpt){
	  logwrite(LOG_NOTICE, "%s => %s@%s <%s@%s> with local\n",
		   msg->uid, rcpt->local_part, rcpt->domain,
		   env_addr->local_part, env_addr->domain
		   );
	}else{
	  logwrite(LOG_NOTICE, "%s => <%s@%s> with local\n",
		   msg->uid, rcpt->local_part, rcpt->domain);
	}
	adr_mark_delivered(rcpt);
	ok = TRUE;
      }
    }

    destroy_header(retpath_hdr);
    destroy_header(envto_hdr);

    g_list_free(hdr_list);
  }
  if(flag) msg_free_data(msg);

  return ok;
}

/* make a list of rcpt's of a message that are local
   return a new copy of the list
*/
GList *msg_rcptlist_local(GList *rcpt_list)
{
  GList *rcpt_local_list = NULL;
  GList *rcpt_node;

  foreach(rcpt_list, rcpt_node){
    address *rcpt = (address *)(rcpt_node->data);
    GList *dom_node;

    DEBUG(5) debugf("checking adress %s\n", rcpt->address);

    /* search for local host list: */
    foreach(conf.local_hosts, dom_node){
      if(strcmp(dom_node->data, rcpt->domain) == 0){
	rcpt_local_list = g_list_append(rcpt_local_list, rcpt);
	DEBUG(5) debugf("<%s@%s> is local\n", rcpt->local_part, rcpt->domain);
	break;
      }
    }
  }
  return rcpt_local_list;
}

/* deliver list of messages to one host
   and finishes them if the message was delivered to at least one
   rcpt.
   Returns TRUE if at least one msg was delivered to at least one
   rcpt.
*/

gboolean deliver_msglist_host(GList *msgout_list, gchar *host, GList *res_list)
{
  gboolean ok = FALSE;
  GList *msgout_node;
  smtp_base *psb;
  smtp_error err;

  /* paranoid check: */
  if(msgout_list == NULL){
    logwrite(LOG_ALERT,
	     "Ooops: empty list of messages in deliver_msglist_host()\n");
    return FALSE;
  }

  if(psb = smtp_out_open(host, conf.remote_port, res_list)){
    if(smtp_out_init(psb)){

      foreach(msgout_list, msgout_node){
	msg_out *msgout = (msg_out *)(msgout_node->data);
	gboolean flag, ok_msg = FALSE;
	message *msg = msgout->msg;

	/* we may have to read the data at this point
	   and remember if we did */
	flag = (msg->data_list == NULL);
	if(flag){
	  if(!spool_read_data(msg)){
	    logwrite(LOG_ALERT, "could not open data spool file %s\n",
		     msg->uid);
	    break;
	  }
	}
    
	smtp_out_msg(psb, msg,
		     msgout->return_path, msgout->rcpt_list, msgout->hdr_list);

	if((psb->error == smtp_eof) ||
	   (psb->error == smtp_timeout)){
	  /* connection lost */
	  break;
	}
	else if(psb->error != smtp_ok){
	  if(g_list_next(msgout_node) != NULL)
	    if(!smtp_out_rset(psb))
	      break;
	}
	ok_msg = (psb->error == smtp_ok);

	if(flag) msg_free_data(msg);
	if(ok_msg){
	  ok = TRUE;
	  /*deliver_finish(msg);*/
	}
      }
      if(psb->error == smtp_ok ||
	 (psb->error == smtp_fail) ||
	 (psb->error == smtp_trylater) ||
	 (psb->error == smtp_syntax)){

	smtp_out_quit(psb);
      }
    }
    destroy_smtpbase(psb);
  }
}

/*
  delivers messages in msgout_list using route
*/
gboolean deliver_route_msgout_list(connect_route *route, GList *msgout_list)
{
  GList *msgout_node;
  gboolean ok = FALSE;

  DEBUG(5) debugf("deliver_route_msgout_list entered, route->name = %s\n",
		  route->name);

  if(route->mail_host != NULL){
    /* this is easy... */
    if(deliver_msglist_host(msgout_list,
			    route->mail_host, route->resolve_list))
      ok = TRUE;
      
  }else{
    /* this is not easy... */
    GList *mo_ph_list;

    mo_ph_list = route_msgout_list(route, msgout_list);
    /* okay, now we have ordered our messages by the hosts. */
    if(mo_ph_list != NULL){
      GList *mo_ph_node;
      /* TODO: It would be nice to be able to fork for each host.
	 We cannot do that yet because of complications with finishing the
	 messages. Threads could be a solution because they use the same
	 memory. But we are not thread safe yet...
      */
      foreach(mo_ph_list, mo_ph_node){
	msgout_perhost *mo_ph = (msgout_perhost *)(mo_ph_node->data);
	if(deliver_msglist_host(mo_ph->msgout_list,
				mo_ph->host, route->resolve_list))
	  ok = TRUE;

	destroy_msgout_perhost(mo_ph);
      }
      g_list_free(mo_ph_list);
    }
  }
  return ok;
}

/*
  calls route_prepare_msg()
  delivers messages in msg_list using route
  by calling deliver_route_msgout_list()
*/
gboolean deliver_route_msg_list(connect_route *route, GList *msgout_list)
{
  GList *msgout_list_deliver = NULL;
  GList *msgout_node;
  gboolean ok = FALSE;

  foreach(msgout_list, msgout_node){
    msg_out *msgout = (msg_out *)(msgout_node->data);
    msg_out *msgout_cloned = clone_msg_out(msgout);
    DEBUG(6) debugf("1 ret path = %s\n", msgout->return_path);
    if(route_strip_msgout(route, msgout_cloned)){
      route_prepare_msgout(route, msgout_cloned);
      DEBUG(6) debugf("2 ret path = %s\n", msgout->return_path);
      msgout_list_deliver = g_list_append(msgout_list_deliver, msgout_cloned);
    }
    else
      destroy_msg_out(msgout_cloned);
  }

  if(msgout_list_deliver != NULL){
    if(deliver_route_msgout_list(route, msgout_list_deliver))
      ok = TRUE;
    destroy_msg_out_list(msgout_list_deliver);
  }
  return ok;
}

#ifdef WITH_ALIASES
/* copy pointers of delivered addresses to the msg's non_rcpt_list,
   to make sure that they will not be delivered again.
*/
void update_non_rcpt_list(msg_out *msgout)
{
  GList *rcpt_node;
  message *msg = msgout->msg;

  DEBUG(6) debugf("update_non_rcpt_list() entered\n");

  foreach(msgout->rcpt_list, rcpt_node){
    address *rcpt = (address *)(rcpt_node->data);
    if(adr_is_delivered(rcpt))
      msg->non_rcpt_list = g_list_append(msg->non_rcpt_list, rcpt);
  }
}
#endif

/* after delivery attempts, we check if there are any
   rcpt addresses left in the message.
   If all addresses have been completed, the spool files will
   be deleted, otherwise the header spool will be written back.
   We never changed the data spool, so there is no need to write that back.

   returns TRUE if all went well.
*/
gboolean deliver_finish(msg_out *msgout)
{
  GList *rcpt_node;
  gboolean ok = FALSE;
  message *msg = msgout->msg;
  gboolean finished = TRUE;

#ifdef WITH_ALIASES
  update_non_rcpt_list(msgout);
  foreach(msg->rcpt_list, rcpt_node){
    address *rcpt = (address *)(rcpt_node->data);
    if(!adr_is_delivered_children(rcpt))
      finished = FALSE;
    else
      adr_mark_delivered(rcpt);
  }
#else
  foreach(msg->rcpt_list, rcpt_node){
    address *rcpt = (address *)(rcpt_node->data);
    if(!adr_is_delivered(rcpt)){
      finished = FALSE;
      break;
    }
  }
#endif

  if(!finished){
    /* one not delivered address was found */
    if(spool_write(msg, FALSE)){
      ok = TRUE;
      DEBUG(2) debugf("spool header for %s written back.\n", msg->uid);
    }else
      logwrite(LOG_ALERT, "could not write back spool header for %s\n",
	       msg->uid);
  }else{
    ok = spool_delete_all(msg);
    if(ok)
      logwrite(LOG_NOTICE, "%s completed.\n", msg->uid);
  }
  return ok;
}

gboolean deliver_finish_list(GList *msgout_list)
{
  gboolean ok = TRUE;
  GList *msgout_node;
  foreach(msgout_list, msgout_node){
    msg_out *msgout = (msg_out *)(msgout_node->data);
    if(!deliver_finish(msgout))
      ok = FALSE;
  }
  return ok;
}
 

/* This function searches in the list of rcpt adresses
   for local and 'local net' adresses. Remote addresses
   which are reachable only when online are treated specially
   in another function.

   deliver() is called when a message has just been received and should
   be delivered immediately.
*/
gboolean deliver(message *msg)
{
  gboolean ok = FALSE;
  msg_out *msgout = create_msg_out(msg);

#ifndef WITH_ALIASES
  msgout->rcpt_list = g_list_copy(msg->rcpt_list);
#else
  GList *alias_table = NULL;
  if(conf.alias_file)
    alias_table = table_read(conf.alias_file, ':');
  msgout->rcpt_list = alias_expand(alias_table, msg->rcpt_list, msg->non_rcpt_list);
#endif

  /* local deliveries */
  {
    GList *rcpt_list = msg_rcptlist_local(msgout->rcpt_list);
    if(rcpt_list != NULL){
      if(deliver_local(msgout, rcpt_list))
	ok = TRUE;
      g_list_free(rcpt_list);
    }
  }

  /* routed local net deliveries: */
  {
    GList *route_node;
    GList *msgout_list = g_list_append(NULL, msgout); /* list with one member */

    foreach(conf.local_net_routes, route_node){
      connect_route *route = (connect_route *)(route_node->data);
      conf.curr_route = route;
      if(deliver_route_msg_list(route, msgout_list))
	ok = TRUE;
      conf.curr_route = NULL;
    }
    g_list_free(msgout_list);
  }

  /* routed online deliveries: */
  {
    GList *rcpt_node;
    /* find out if there is still any rcpt to be deliverd,
       because otherwise we do not need the effort of detecting online
       and reading the route file.
       There should be a better way: not delivered does not mean that
       the rcpt is for an online route, could have been a failure.
    */
    foreach(msgout->rcpt_list, rcpt_node){
      address *rcpt = (address *)(rcpt_node->data);
      if(!adr_is_delivered(rcpt))
	break;
    }
    
    if(rcpt_node != NULL){
      gchar *route_name = detect_online();
      if(route_name != NULL){
	/* we are online! */
	GList *msgout_list = g_list_append(NULL, msgout); /* list with one member */

	connect_route *route = find_route(conf.connect_routes, route_name);
	if(route != NULL){
	  if(read_route(route, FALSE)){
	    conf.curr_route = route;

	    if(deliver_route_msg_list(route, msgout_list))
	      ok = TRUE;

	    conf.curr_route = NULL;
	  }
	  else
	    logwrite(LOG_ALERT,
		     "could not read route file '%s'\n", route->filename);
	}else{
	  logwrite(LOG_ALERT, "route with name '%s' not found.\n", route_name);
	}
	g_list_free(msgout_list);
      }
    }
  }

#ifdef WITH_ALIASES
  destroy_table(alias_table);
#endif

  if(ok) deliver_finish(msgout);

  destroy_msg_out(msgout);

  return ok;
}
