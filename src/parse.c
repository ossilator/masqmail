/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth

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

#ifndef PARSE_TEST
#include "masqmail.h"
#endif

/* This is really dangerous. I hope that I was careful enough,
   but maybe there is some malformed address possible that causes
   this to segfault or be caught in endless loops.

   If you find something like that, PLEASE mail the string to me
   (no matter how idiotic it is), so that I can debug that.
   Those things really should not happen.
*/

static gchar *specials = "()<>@,;:\\\".[]";

char *parse_error = NULL;

static
gchar *skip_comment(gchar *p)
{

#ifdef PARSE_TEST
  g_print("skip_comment: %s\n", p);
#endif

  p++;
  while(*p && *p != ')'){
    p++;
    if(*p == '(')
      p = skip_comment(p);
  }
  p++;

  return p;
}

static
gboolean read_word(gchar *p, gchar **b, gchar **e)
{
#ifdef PARSE_TEST
  g_print("read_word: %s\n", p);
#endif
  /* eat leading spaces */
  while(*p && isspace(*p)) p++;
  
  *b = p;
  /*  b = &p;*/
  if(*p == '\"'){
    /* quoted-string */
    p++;
    while(*p && (*p != '\"')) p++;
    p++;
  }else{
    /* atom */
    while(*p && !strchr(specials, *p) && !iscntrl(*p) && !isspace(*p))
      p++;
  }
  *e = p;
  return TRUE;
}

static
gboolean read_word_with_dots(gchar *p, gchar **b, gchar **e)
{
  gchar *b0 = p;

#ifdef PARSE_TEST
  g_print("read_word_with_dots: %s\n", p);
#endif
  while(TRUE){
    if(!read_word(p, b, e))
      return FALSE;
    p = *e;
    if(*p != '.') break;
    p++;
  }
  *b = b0;
  *e = p;
  return TRUE;
}

static
gboolean read_domain(gchar *p, gchar **b, gchar **e)
{
#ifdef PARSE_TEST
  g_print("read_domain: %s\n", p);
#endif
  *b = p;
  if(*p != '['){
    while(isalnum(*p) || (*p == '-') || (*p == '.'))
      p++;
  }else{
    p++;
    while(isalpha(*p) || (*p == '.'))
      p++;
    if(*p != ']'){
      parse_error =
	g_strdup_printf("']' expected at end of literal address %s", *b);
      return FALSE;
    }
    p++;
  }
  *e = p;
  return TRUE;
}

gboolean parse_address_rfc822(gchar *string,
		       gchar **local_begin, gchar **local_end,
		       gchar **domain_begin, gchar **domain_end,
		       gchar **address_end)
{
  gint angle_brackets = 0;

  gchar *p = string;
  gchar *b, *e;

  *local_begin = *local_end = NULL;
  *domain_begin = *domain_end = NULL;

  /* might be some memory left from previous call: */
  if(parse_error != NULL){
    g_free(parse_error);
    parse_error = NULL;
  }

  /* leading spaces and angle brackets */
  while(*p && (isspace(*p) || (*p == '<'))){
    if(*p == '<')
      angle_brackets++;
    p++;
  }
 
  if(*p){
    while(TRUE){
      if(read_word_with_dots(p, &b, &e)){
	p = e;
#ifdef PARSE_TEST
	g_print("after read_word_with_dots: %s\n", p);
#endif
	/* eat white spaces and comments */
	while((*p && (isspace(*p))) || (*p == '(')){
	  if(*p == '('){
	    if(!(p = skip_comment(p))){
	      parse_error =
		g_strdup("missing right bracket ')'");
	      return FALSE;
	    }
	  }else
	    p++;
	}
	/* we now have a non-space char that is not
	   the beginning of a comment */

	if(*p == '@'){
	  /* the last word was the local_part
	     of an addr-spec */
	  *local_begin = b;
	  *local_end = e;
#ifdef PARSE_TEST
	  g_print("found local part: %s\n", *local_begin);
#endif
	  if(*p == '@'){
	    p++; /* skip @ */
	    /* now the domain */
	    if(read_domain(p, &b, &e)){
	      p = e;
	      *domain_begin = b;
	      *domain_end = e;
	    }
	    else
	      return FALSE;
	  }else{
	    /* unqualified? */
	    *domain_begin = *domain_end = NULL;
	  }
	  break;
	}else if(*p == '<'){
	  /* addr-spec follows */
	  while(isspace(*p) || (*p == '<')){
	    if(*p == '<')
	      angle_brackets++;
	    p++;
	  }
	  if(read_word_with_dots(p, &b, &e)){
	    p = e;
	    *local_begin = b;
	    *local_end = e;
#ifdef PARSE_TEST
	  g_print("found local part: %s\n", *local_begin);
#endif
	  }else
	    return FALSE;
	  if(*p == '@'){
	    p++;
	    if(read_domain(p, &b, &e)){
	      p = e;
	      *domain_begin = b;
	      *domain_end = e;
	    }else
	      return FALSE;
	  }else{
	    /* may be unqualified address */
	    *domain_begin = *domain_end = NULL;
	  }
	  break;
	}else if(!*p || *p == '>'){
	  *local_begin = b;
	  *local_end = e;
#ifdef PARSE_TEST
	  g_print("found local part: %s\n", *local_begin);
#endif
	  *domain_begin = *domain_end = NULL;
	  break;
	}else if(strchr(specials, *p) || iscntrl(*p) || isspace(*p)){
	  parse_error = g_strdup_printf("unexpected character: %c", *p);
	  return FALSE;
	}
      }else
	return FALSE;
    }
   /* trailing spaces and angle brackets */
#ifdef PARSE_TEST
    g_print("down counting trailing '>'\n");
#endif
    while(*p && (isspace(*p) || (*p == '>'))){
      if(*p == '>')
	angle_brackets--;
      p++;
    }

    *address_end = p;

    if(angle_brackets != 0){
      if(angle_brackets > 0)
	parse_error = g_strdup("missing '>' at end of string");
      else
	parse_error = g_strdup("superfluous '>' at end of string");
      return FALSE;
    }else{
      /* we successfully parsed the address */
      return TRUE;
    }
    /* we never get here */
  }
  return FALSE;
}

gboolean parse_address_rfc821(gchar *string,
			      gchar **local_begin, gchar **local_end,
			      gchar **domain_begin, gchar **domain_end,
			      gchar **address_end)
{
  gint angle_brackets = 0;

  gchar *p = string;
  gchar *b, *e;

  *local_begin = *local_end = NULL;
  *domain_begin = *domain_end = NULL;

  /* might be some memory left from previous call: */
  if(parse_error != NULL){
    g_free(parse_error);
    parse_error = NULL;
  }

  /* leading spaces and angle brackets */
  while(*p && (isspace(*p) || (*p == '<'))){
    if(*p == '<')
      angle_brackets++;
    p++;
  }
 
  if(*p){
    while(TRUE){
      if(read_word_with_dots(p, &b, &e)){
	p = e;
#ifdef PARSE_TEST
	g_print("after read_word_with_dots: %s\n", p);
#endif
	*local_begin = b;
	*local_end = e;
#ifdef PARSE_TEST
	  g_print("found local part: %s\n", *local_begin);
	  g_print("local_end = %s\n", *local_end);
#endif
	if(!(*p) || isspace(*p) || (*p == '>')){
	  /* unqualified ?*/
	  domain_begin = domain_end = NULL;
	  break;
	}else if(*p == '@'){
	  p++;
	  if(read_domain(p, &b, &e)){
	    p = e;
	    *domain_begin = b;
	    *domain_end = e;
	  }
	  break;
	}else{
	  parse_error =
	      g_strdup_printf("unexpected character after local part '%c'",*p);
	  return FALSE;
	}
      } else
         return FALSE;
    }

    /* trailing spaces and angle brackets */
#ifdef PARSE_TEST
    g_print("down counting trailing '>'\n");
#endif
    while(*p && (isspace(*p) || (*p == '>'))){
      if(*p == '>')
	angle_brackets--;
      p++;
    }
    *address_end = p;

    if(angle_brackets != 0){
      if(angle_brackets > 0)
	parse_error = g_strdup("missing '>' at end of string");
      else
	parse_error = g_strdup("superfluous '>' at end of string");
      return FALSE;
    }else{
      /* we successfully parsed the address */
      return TRUE;
    }
    /* we never get here */
  }
  return FALSE;
}

/*
  allocate address, reading from string.
  On failure, returns NULL.
  after call, end contatins a pointer to the end of the parsed string
  end may be NULL, if we are not interested.

  parses both rfc 821 and rfc 822 addresses, depending on flag is_rfc821
*/

address *_create_address(gchar *string, gchar **end, gboolean is_rfc821)
{
  gchar *loc_beg, *loc_end;
  gchar *dom_beg, *dom_end;
  gchar *addr_end;

  if (string && (string[0] == 0)) {
    address *addr = g_malloc(sizeof(address));
    addr->address = g_strdup("");
    addr->local_part = g_strdup("");
    addr->domain = g_strdup(""); /* 'NULL' address (failure notice),
        "" makes sure it will not be qualified with a hostname */
    return addr;
  }

  if(is_rfc821 ?
     parse_address_rfc821(string,
			  &loc_beg, &loc_end, &dom_beg, &dom_end, &addr_end) :
     parse_address_rfc822(string,
			  &loc_beg, &loc_end, &dom_beg, &dom_end, &addr_end)){
    address *addr = g_malloc(sizeof(address));
    gchar *p = addr_end;
    

    memset(addr, 0, sizeof(address));

    if(loc_beg[0] == '|'){
      parse_error = g_strdup("no pipe allowed for RFC 822/821 address");
      return NULL;
    }

    while(*p && (*p != ',')) p++;
    addr->address = g_strndup(string, p - string);

    addr->local_part = g_strndup(loc_beg, loc_end - loc_beg);

#ifdef PARSE_TEST
    g_print("addr->local_part = %s\n", addr->local_part);
#endif

    if(dom_beg != NULL){
      addr->domain = g_strndup(dom_beg, dom_end - dom_beg);
    }else{
      if(addr->local_part[0] == 0)
	addr->domain = g_strdup(""); /* 'NULL' address (failure notice),
		      "" makes sure it will not be qualified with a hostname */
      else
	addr->domain = NULL;
    }

    if(end != NULL)
      *end = p;

#ifndef PARSE_TEST
    addr_unmark_delivered(addr);
#endif

    return addr;
  }
  return NULL;
}

address *create_address_rfc822(gchar *string, gchar **end){
  return _create_address(string, end, FALSE);
}

address *create_address_rfc821(gchar *string, gchar **end){
  return _create_address(string, end, TRUE);
}

GList *addr_list_append_rfc822(GList *addr_list, gchar *string, gchar *domain)
{
  gchar *p = string;
  gchar *end;

  while(*p){
    address *addr = _create_address(p, &end, FALSE);
    if(addr){
      if(domain)
	if(addr->domain == NULL)
	  addr->domain = g_strdup(domain);

      addr_list = g_list_append(addr_list, addr);
      p = end;
    }else
      break;
    while(*p == ',' || isspace(*p)) p++;
  }
  return addr_list;
}
