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

#ifndef REWRITE_TEST
#include "masqmail.h"
#endif

gboolean set_address_header_domain(header *hdr, gchar *domain)
{
  gchar *p = hdr->value;
  gchar *new_hdr = g_strndup(hdr->header, hdr->value - hdr->header);
  gint tmp;

  while(*p){
    gchar *loc_beg, *loc_end;
    gchar *dom_beg, *dom_end;
    gchar *adr_end;
    gchar *rewr_string;

    if(parse_address_rfc822(p,
			    &loc_beg, &loc_end, &dom_beg, &dom_end, &adr_end)){
      gchar *left, *right;

      if(dom_beg != NULL){
	left = g_strndup(p, dom_beg - p);
	right = g_strndup(dom_end, adr_end - dom_end);

	rewr_string = g_strconcat(left, domain, right, NULL);
      }else{
	left = g_strndup(p, loc_end - p);
	right = g_strndup(loc_end, adr_end - loc_end);

	rewr_string = g_strconcat(left, "@", domain, right, NULL);
      }
      g_free(left);
      g_free(right);

      p = adr_end;
      if(*p == ',') p++;

      new_hdr =
	g_strconcat(new_hdr, rewr_string,
		    *p != 0 ? "," : NULL, NULL);

    }else
      return FALSE;
  }
  tmp = (hdr->value - hdr->header);
  g_free(hdr->header);
  hdr->header = new_hdr;
  hdr->value = hdr->header + tmp;

  return TRUE;
}

gboolean map_address_header(header *hdr, GList *table)
{
  GList *adr_list = adr_list_append_rfc822(NULL, hdr->value, conf.host_name);
  GList *adr_node;
  gchar *new_hdr = g_strndup(hdr->header, hdr->value - hdr->header);
  gboolean did_change = FALSE;

  foreach(adr_list, adr_node){
    address *adr = (address *)(adr_node->data);
    gchar *rewr_string = (gchar *)table_find_fnmatch(table, adr->local_part);

    if(rewr_string == NULL)
      rewr_string = adr->address;
    else
      did_change = TRUE;

    if(rewr_string)
      new_hdr =
	g_strconcat(new_hdr, rewr_string,
		    g_list_next(adr_node) ? "," : "\n", NULL);
  }
  if(did_change){
    g_free(hdr->header);
    hdr->header = new_hdr;
  }else
    g_free(new_hdr);

  return did_change;
}

