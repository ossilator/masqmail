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

#define MAX_VAR 50

gint expand(GList *var_list, gchar *format, gchar *result, gint result_len)
{
  gchar *p = format, *q = result;
  gchar *var = NULL, *vq;
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

