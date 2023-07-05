/*  MasqMail
    Copyright (C) 2000 Oliver Kurth

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

/* static */
/* gchar *str_unquote(gchar *str) */
/* { */
/*   if(str[0] == '\"'){ */
/*     gchar *p = str; p++; */
/*     while(*p && (*p != '\"' || p[-1] == '\\')) p++; */
/*     *p = 0; */
/*     return str+1; */
/*   } */
/*   return str; */
/* } */

static
gboolean adr_is_local(address *adr)
{
  GList *dom_node;

  foreach(conf.local_hosts, dom_node){
    if(adr->domain == NULL)
      return TRUE;
    if(strcmp(dom_node->data, adr->domain) == 0)
      return TRUE;
  }
  return FALSE;
}

static
GList *parse_list(gchar *line)
{
  GList *list = NULL;
  gchar buf[256];
  gchar *p, *q;

  p = line;
  while(*p != 0){
    q = buf;
    while(isspace(*p)) p++;
    if(*p != '\"'){
      while(*p && (*p != ','))
	*(q++) = *(p++);
      *q = 0;
    }else{
      p++;
      while(*p && (*p != '\"' || p[-1] == '\\'))
	*(q++) = *(p++);
      *q = 0;
      while(*p && (*p != ',')) p++;
    }
    list = g_list_append(list, g_strdup(g_strchomp(buf)));
    if(*p) p++;
  }
  return list;
}

GList *alias_expand(GList *alias_table, GList *rcpt_list, GList *non_rcpt_list)
{
  GList *done_list = NULL;
  GList *rcpt_node = g_list_copy(rcpt_list);

  while(rcpt_node != NULL){
    address *adr = (address *)(rcpt_node->data);
    DEBUG(5) debugf("alias_expand begin: '%s@%s'\n", adr->local_part, adr->domain);
    if(adr_is_local(adr) && (adr->local_part[0] != '|') && !(adr->flags & ADDR_FLAG_NOEXPAND)){
      gchar *val = (gchar *)table_find(alias_table, adr->local_part);
      DEBUG(5) debugf("alias: '%s' is local\n", adr->local_part);
      if(val != NULL){
	GList *val_list = parse_list(val);
	GList *val_node;
	GList *alias_list = NULL;

	DEBUG(5) debugf("alias: '%s' -> '%s'\n", adr->local_part, val);
	foreach(val_list, val_node){
	  gchar *val = (gchar *)(val_node->data);
	  address *alias_adr;
	  address *adr_parent = NULL;

	  if(val[0] == '|')
	    alias_adr = create_address_pipe(val);
	  else if(val[0] == '\\'){
	    alias_adr = create_address_qualified(&(val[1]), TRUE, conf.host_name);
	    alias_adr->flags |= ADDR_FLAG_NOEXPAND;
	  }else{
	    alias_adr = create_address_qualified(val, TRUE, conf.host_name);

	    /* search in parents for loops: */
	    for(adr_parent = adr; adr_parent; adr_parent = adr_parent->parent){
	      if(addr_isequal(alias_adr, adr_parent)){
		logwrite(LOG_ALERT, "detected alias loop, (ignoring): %s@%s -> %s@%s\n",
			 adr_parent->local_part, adr_parent->domain, adr->local_part, adr->domain);
		break;
	      }
	    }
	  }
	  if(!adr_parent){
	    alias_list = g_list_append(alias_list, alias_adr);
	    alias_adr->parent = adr;
	  }
	  g_free(val);
	}
	g_list_free(val_list);
	adr->children = g_list_copy(alias_list);
	rcpt_node = g_list_concat(rcpt_node, alias_list);
      }else{
	DEBUG(5) debugf("alias: '%s' is completed\n", adr->local_part);
	done_list = g_list_append(done_list, adr);
      }
    }else{
      DEBUG(5) debugf("alias: '%s@%s' is not local\n", adr->local_part, adr->domain);
      done_list = g_list_append(done_list, adr);
    }
    rcpt_node = g_list_next(rcpt_node);
  }

  /* delete addresses from done_list if they are in the non_rcpt_list */
  if(non_rcpt_list){
    GList *rcpt_node_next;
    for(rcpt_node = g_list_first(done_list);
	 rcpt_node;
	 rcpt_node = rcpt_node_next){
      address *adr = (address *)(rcpt_node->data);
      GList *non_node;

      rcpt_node_next = g_list_next(rcpt_node);

      foreach(non_rcpt_list, non_node){
	address *non_adr = (address *)(non_node->data);
	if(addr_isequal(adr, non_adr)){
	  done_list = g_list_remove_link(done_list, rcpt_node);
	  g_list_free_1(rcpt_node);
	  adr_mark_delivered(adr); /* this address is still in the children lists
				      of the original address */
	  break;
	}
      }
    }
  }
  return done_list;
}
