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

table_pair *parse_table_pair(gchar *line, char delim)
{
  gchar *adr;
  gchar *port;
  gchar buf[256];
  gchar *p, *q;
  table_pair *pair;

  DEBUG(6) fprintf(stderr, "parse_table_pair: %s\n", line);

  p = line;
  q = buf;
  while((*p != 0) && (*p != delim))
    *(q++) = *(p++);
  *q = 0;

  pair = g_malloc(sizeof(table_pair));
  pair->key = g_strdup(g_strstrip(buf));

  if(*p){
    p++;
    /*    while(isspace(*p)) p++; */
    pair->value = (gpointer *)(g_strdup(g_strstrip(p)));
  }else
    pair->value = (gpointer *)g_strdup("");

  return pair;
}

gpointer *table_find(GList *table_list, gchar *key)
{
  GList *node;

  foreach(table_list, node){
    table_pair *pair = (table_pair *)(node->data);
    if(strcmp(key, pair->key) == 0)
      return pair->value;
  }
  return NULL;
}

GList *table_read(gchar *fname, gchar delim)
{
  GList *list = NULL;
  FILE *fptr;

  if(fptr = fopen(fname, "rt")){
    gchar buf[256];

    while(fgets(buf, 255, fptr)){
      if(buf[0] && (buf[0] != '#') && (buf[0] != '\n')){
	table_pair *pair;
	g_strchomp(buf);
	pair = parse_table_pair(buf, delim);
	list = g_list_append(list, pair);
      }
    }
    fclose(fptr);
    return list;
  }
  logwrite(LOG_ALERT, "could not open table file %s: %s\n", fname, strerror(errno));

  return NULL;
}

void destroy_table(GList *table)
{
  GList *node;

  foreach(table, node){
    table_pair *p = (table_pair *)(node->data);
    g_free(p->key);
    g_free(p->value);
  }
  g_list_free(table);
}

