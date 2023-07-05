/*  MasqMail
    Copyright (C) 2000-2001 Oliver Kurth

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

#define MAX_VAR 50

GList *var_table_rcpt(GList *var_table, address *rcpt)
{
    gchar *tmp_str;
    
    var_table = g_list_prepend(var_table, create_pair_string("rcpt_local", rcpt->local_part));
    var_table = g_list_prepend(var_table, create_pair_string("rcpt_domain", rcpt->domain));
    
    tmp_str = g_strdup_printf("%s@%s", rcpt->local_part, rcpt->domain);
    var_table = g_list_prepend(var_table, create_pair_string("rcpt", tmp_str));
    g_free(tmp_str);

    return var_table;
}

GList *var_table_msg(GList *var_table, message *msg)
{
    address *ret_path = msg->return_path;
    gchar *tmp_str;
    
    var_table = g_list_prepend(var_table, create_pair_string("uid", msg->uid));
    var_table = g_list_prepend(var_table, create_pair_string("received_host",
							    msg->received_host ? msg->received_host : ""));
    var_table = g_list_prepend(var_table, create_pair_string("ident", msg->ident ? msg->ident : ""));
    var_table = g_list_prepend(var_table, create_pair_string("return_path_local", ret_path->local_part));
    var_table = g_list_prepend(var_table, create_pair_string("return_path_domain", ret_path->domain));
    
    tmp_str = g_strdup_printf("%s@%s", ret_path->local_part, ret_path->domain);
    var_table = g_list_prepend(var_table, create_pair_string("return_path", tmp_str));
    g_free(tmp_str);

    return var_table;
}

GList *var_table_conf(GList *var_table)
{
    var_table = g_list_prepend(var_table, create_pair_string("host_name", conf.host_name));
    var_table = g_list_prepend(var_table, create_pair_string("package", PACKAGE));
    var_table = g_list_prepend(var_table, create_pair_string("version", VERSION));

    return var_table;
}

gint expand(GList *var_list, gchar *format, gchar *result, gint result_len)
{
  gchar *p = format, *q = result;
  gchar *vq;
  gint i = 0;
  gboolean escape = FALSE;

  while(*p && (i < (result_len -1))){
    if((*p == '$') && !escape){
      gchar *value;
      gchar var[MAX_VAR+1];
      int j = 0;

      p++; /* skip '$' */
      vq = var;

      if(*p == '{'){
	/* ${var} style */
	p++; /* skip '{' */
	while(*p && (*p != '}') && (j < MAX_VAR)){
	  *(vq++) = *(p++);
	  j++;
	}
	p++;
      }else{
	/* $var style */
	while(*p && (isalnum(*p) || (*p == '_') || (*p == '-')) && (j < MAX_VAR)){
	  *(vq++) = *(p++);
	  j++;
	}
      }
      *vq = 0;

      if(j < MAX_VAR){
	/* search var */
	value = (gchar *)table_find(var_list, var);
	if(value){
	  gchar *vp = value;
	  while(*vp && (i < (result_len -1))){
	    *(q++) = *(vp++); i++;
	  }
	}
      }
    }else{
      if((*p == '\\') && (!escape)){
	escape = TRUE;
      }else{
	*(q++) = *p; i++;
	escape = FALSE;
      }
      p++;
    }
  }
  *q = 0;

  if(i >= (result_len -1))
    return -3;

  return i;
}

