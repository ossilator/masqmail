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

message *create_message()
{
  message *msg = (message *)g_malloc(sizeof(message));
  if(msg){
    msg->uid = NULL;

    msg->received_host = NULL;
    msg->transfer_id = 0;

    msg->return_path = NULL;
    msg->rcpt_list = NULL;
    msg->non_rcpt_list = NULL;

    msg->hdr_list = NULL;
    msg->data_list = NULL;

    msg->data_size = -1;
    msg->received_time = 0;
  }
  return msg;
}

gint calc_size(message *msg, gboolean is_smtp)
{
  GList *node;
  gint l_cnt = 0, c_cnt = 0;

  /* header size */
  if(msg->hdr_list){
    for(node = g_list_first(msg->hdr_list); node; node = g_list_next(node)){
      if(node->data){
	header *hdr = (header *)(node->data);
	if(hdr->header){
	  char *p = hdr->header;
	  while(*p){
	    if(*p++ == '\n') l_cnt++;
	    c_cnt++;
	  }
	}
      }
    }
  }

  /* empty line separating headers from data: */
  c_cnt++;
  l_cnt++;

  /* data size */
  if(msg->data_list){
    for(node = g_list_first(msg->data_list); node; node = g_list_next(node)){
      if(node->data){
	char *p = node->data;
	while(*p){
	  if(*p++ == '\n') l_cnt++;
	  c_cnt++;
	}
      }
    }
  }

  return is_smtp ? c_cnt + l_cnt : c_cnt;
}

void msg_free_data(message *msg)
{
  GList *node;

  DEBUG(5) debugf("msg_free_data entered\n");

  if(msg->data_list){
    for(node = g_list_first(msg->data_list); node; node = g_list_next(node)){
      if(node->data)
	g_free(node->data);
    }
    g_list_free(msg->data_list);
    msg->data_list = NULL;
  }
}

void destroy_message(message *msg)
{
  GList *node;

  DEBUG(6) debugf("destroy_message entered\n");

  if(msg->uid) g_free(msg->uid);
  if(msg->return_path) g_free(msg->return_path);

  if(msg->rcpt_list){
    for(node = g_list_first(msg->rcpt_list); node; node = g_list_next(node)){
      if(node->data)
	g_free(node->data);
    }
    g_list_free(msg->rcpt_list);
  }
  if(msg->hdr_list){
    for(node = g_list_first(msg->hdr_list); node; node = g_list_next(node)){
      if(node->data){
	header *hdr = (header *)(node->data);
	if(hdr->header)
	  g_free(hdr->header);
	g_free(node->data);
      }
    }
    g_list_free(msg->hdr_list);
  }

  msg_free_data(msg);

  g_free(msg);
}

void destroy_msg_list(GList *msg_list)
{
  GList *msg_node;

  DEBUG(6) debugf("destroy_msg_list entered\n");

  foreach(msg_list, msg_node){
    message *msg = (message *)(msg_node->data);
    destroy_message(msg);
  }
  g_list_free(msg_list);
}

msg_out *create_msg_out(message *msg)
{
  msg_out *msgout = NULL;

  msgout = g_malloc(sizeof(msg_out));
  if(msgout){
    msgout->msg = msg;
    msgout->return_path = NULL;
    msgout->rcpt_list = NULL;
    
    msgout->hdr_list = NULL;
    msgout->xtra_hdr_list = NULL;
  }
  return msgout;
}

msg_out *clone_msg_out(msg_out *msgout_orig)
{
  if(msgout_orig){
    msg_out *msgout = create_msg_out(msgout_orig->msg);
    if(msgout){
      msgout->msg = msgout_orig->msg;
      if(msgout_orig->return_path)
	msgout->return_path = copy_address(msgout_orig->return_path);
      if(msgout_orig->hdr_list)
	msgout->hdr_list = g_list_copy(msgout_orig->hdr_list);
      /* FIXME: if this lives longer than the original
	 and we access one of the xtra hdrs, we will segfault
	 or cause some weird bugs: */
      msgout->xtra_hdr_list = NULL;
      if(msgout_orig->rcpt_list)
	msgout->rcpt_list = g_list_copy(msgout_orig->rcpt_list);
    }
    return msgout;
  }
  return NULL;
}

GList *create_msg_out_list(GList *msg_list)
{
  GList *msgout_list = NULL;
  GList *msg_node;

  foreach(msg_list, msg_node){
    message *msg = (message *)(msg_node->data);
    msgout_list = g_list_append(msgout_list, create_msg_out(msg));
  }
  return msgout_list;
}

void destroy_msg_out(msg_out *msgout)
{
  DEBUG(6) debugf("destroy_msg_out entered\n");

  if(msgout){
    if(msgout->return_path)
      destroy_address(msgout->return_path);
    if(msgout->hdr_list)
      g_list_free(msgout->hdr_list);
    if(msgout->xtra_hdr_list){
      GList *hdr_node;
      foreach(msgout->xtra_hdr_list, hdr_node){
	header *hdr = (header *)(hdr_node->data);
	destroy_header(hdr);
      }
      g_list_free(msgout->xtra_hdr_list);
    }
    g_free(msgout);
  }
  DEBUG(6) debugf("destroy_msg_out returning\n");
}

void destroy_msg_out_list(GList *msgout_list)
{
  GList *msgout_node;
  DEBUG(6) debugf("destroy_msg_out_list entered\n");

  foreach(msgout_list, msgout_node){
    msg_out *msgout = (msg_out *)(msgout_node->data);
    destroy_msg_out(msgout);
  }
  g_list_free(msgout_list);

  DEBUG(6) debugf("destroy_msg_out_list returning\n");
}

address *create_address(gchar *path, gboolean is_rfc821)
{
  address *adr;
  adr = _create_address(path, NULL, is_rfc821);
  
  if(adr != NULL){
    adr_unmark_delivered(adr);
  }
  return adr;
}

address *create_address_qualified(gchar *path, gboolean is_rfc821,
				  gchar *domain)
{
  address *adr = create_address(path, is_rfc821);
  if(adr->domain == NULL)
    adr->domain = g_strdup(domain);

  return adr;
}

/* nothing special about pipes here,
   but its only called for that purpose */
address *create_address_pipe(gchar *path)
{
  address *adr = g_malloc(sizeof(address));

  adr->address = g_strdup(path);
  adr->local_part = g_strdup(path);
  
  adr->domain = g_strdup("localhost"); /* quick hack */
  adr->children = NULL;
  adr->parent = NULL;
}

void destroy_address(address *adr)
{
  DEBUG(6) debugf("destroy_address entered\n");

  g_free(adr->address);
  g_free(adr->local_part);
  g_free(adr->domain);

  g_free(adr);
}

address *copy_modify_address(const address *orig, gchar *l_part, gchar *dom)
{
  address *adr = NULL;

  if(orig){
    adr = g_malloc(sizeof(address));
    if(adr){
      adr->address = g_strdup(orig->address);

      if(l_part == NULL)
	adr->local_part = g_strdup(orig->local_part);
      else
	adr->local_part = g_strdup(l_part);

      if(dom == NULL)
	adr->domain = g_strdup(orig->domain);
      else
	adr->domain = g_strdup(dom);
      adr->children = NULL;
      adr->parent = NULL;
    }
  }
  return adr;
}

gboolean addr_isequal(address *adr1, address *adr2)
{
  return
    (strcmp(adr1->local_part, adr2->local_part) == 0) &&
    (strcasecmp(adr1->domain, adr2->domain) == 0);
}

/* careful, this is recursive */
gboolean adr_is_delivered_children(address *adr)
{
  GList *adr_node;

  DEBUG(6) debugf("adr_is_delivered_children() entered\n"); 

  if(adr->children == NULL) return adr_is_delivered(adr);

  foreach(adr->children, adr_node){
    address *adr = (address *)(adr_node->data);
    if(!adr_is_delivered_children(adr))
      return FALSE;
  }
  return TRUE;
}

/* find original address */
address *addr_find_ancestor(address *adr)
{
  while(adr->parent) adr = adr->parent;
  return adr;
}

