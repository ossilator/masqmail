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

#include "pwd.h"
#include "grp.h"

masqmail_conf conf;

static
void init_conf()
{
  {
    struct passwd *passwd;
    struct group *group;

    if(passwd = getpwnam(DEF_MAIL_USER))
      conf.mail_uid = passwd->pw_uid;
    else{
      fprintf(stderr, "user %s not found! (terminating)\n", DEF_MAIL_USER);
      exit(EXIT_FAILURE);
    }
    if(group = getgrnam(DEF_MAIL_GROUP))
      conf.mail_gid = group->gr_gid;
    else{
      fprintf(stderr, "group %s not found! (terminating)\n", DEF_MAIL_GROUP);
      exit(EXIT_FAILURE);
    }
  }

}

static gchar *true_strings[] =
{
  "yes", "on", "true", NULL
};

static gchar *false_strings[] =
{
  "no", "off", "false", NULL
};

static
gboolean parse_boolean(gchar *rval)
{
  gchar **str;

  DEBUG(6) fprintf(stderr, "parse_boolean: %s\n", rval);

  str = true_strings;
  while(*str){
    if(strncasecmp(*str, rval, strlen(*str)) == 0)
      return TRUE;
    str++;
  }

  str = false_strings;
  while(*str){
    if(strncasecmp(*str, rval, strlen(*str)) == 0)
      return FALSE;
    str++;
  }

  fprintf(stderr, "cannot parse value '%s'\n", rval);
  exit(EXIT_FAILURE);
}

/* make a list from each line in a file */
static
GList *parse_list_file(gchar *fname)
{
  GList *list = NULL;
  FILE *fptr;

  if(fptr = fopen(fname, "rt")){
    gchar buf[256];

    while(!feof(fptr)){
      fgets(buf, 255, fptr);
      if(buf[0] && (buf[0] != '#') && (buf[0] != '\n')){
	g_strchomp(buf);
	list = g_list_append(list, g_strdup(buf));
      }
    }
    fclose(fptr);
  }
  return list;
}

/* given a semicolon separated string, this function
   makes a GList out of it.
*/
GList *parse_list(gchar *line, gboolean read_file)
{
  GList *list = NULL;
  gchar buf[256];
  gchar *p, *q;

  DEBUG(6) fprintf(stderr, "parsing list %s\n", line);

  p = line;
  while(*p != 0){
    q = buf;

    while(*p && (*p != ';'))
      *(q++) = *(p++);
    *q = 0;

    if((buf[0] == '/') && (read_file))
      /* item is a filename, include its contents */
      list = g_list_concat(list, parse_list_file(buf));
    else
      /* just a normal item */
      list = g_list_append(list, g_strdup(buf));

    DEBUG(6) printf("item = %s\n", buf);

    if(*p) p++;
  }
  return list;
}

static
interface *parse_interface(gchar *line, gint def_port)
{
  gchar *adr;
  gchar *port;
  gchar buf[256];
  gchar *p, *q;
  interface *iface;

  DEBUG(6) fprintf(stderr, "parse_interface: %s\n", line);

  p = line;
  q = buf;
  while((*p != 0) && (*p != ':'))
    *(q++) = *(p++);
  *q = 0;

  iface = g_malloc(sizeof(interface));
  iface->address = g_strdup(buf);

  if(*p){
    p++;
    iface->port = atoi(p);
  }else
    iface->port = def_port;

  return iface;
}

static
gboolean eat_comments(FILE *in)
{
  gint c;

  for(c = fgetc(in); (c == '#' || c == '\n') && c != EOF; c = fgetc(in)){
    if(c == '#'){
      gint c;
      for(c = fgetc(in); (c != '\n') && (c != EOF); c = fgetc(in));
    }
  }
  if(c == EOF) return FALSE;
  ungetc(c, in);
  return TRUE;
}

/* after parsing, eat trailing character until LF */
static
gboolean eat_line_trailing(FILE *in)
{
  gint c;

  for(c = fgetc(in); c != EOF && c != '\n'; c = fgetc(in));
  if(c == EOF) return FALSE;
  return TRUE;
}

static
gboolean eat_spaces(FILE *in)
{
  gint c;
  
  for(c = fgetc(in); c != EOF && isspace(c); c = fgetc(in));
  if(c == EOF) return FALSE;
  ungetc(c, in);
  return TRUE;
}

static
gboolean read_lval(FILE *in, gchar *buf, gint size)
{
  gint c;
  gchar *ptr = buf;
  
  DEBUG(6) fprintf(stderr, "read_lval()\n");

  if(!eat_spaces(in)) return FALSE;

  c = fgetc(in);
  DEBUG(6) fprintf(stderr, "read_lval() 2\n");
  while((isalnum(c) || c == '_' || c == '-' || c == '.')
	&& (ptr < buf+size)
	&& (c != EOF)
	){
    *ptr = c; ptr++;
    c = fgetc(in);
  }
  *ptr = 0;
  ungetc(c, in);

  if(c == EOF){
    fprintf(stderr, "unexpected EOF after %s\n", buf);
    return FALSE;
  }else if(ptr >= buf+size){
    fprintf(stderr, "lval too long\n");
  }

  eat_spaces(in);

  DEBUG(6) fprintf(stderr, "lval = %s\n", buf);

  return buf[0] != 0;
}

static
gboolean read_rval(FILE *in, gchar *buf, gint size)
{
  gint c;
  gchar *ptr = buf;
  
  DEBUG(6) fprintf(stderr, "read_rval()\n");

  if(!eat_spaces(in)) return FALSE;

  c = fgetc(in);
  if(c != '\"'){
    while((isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/')
	  && (ptr < buf+size)
	  && (c != EOF)
	  ){
      *ptr = c; ptr++;
      c = fgetc(in);
    }
    *ptr = 0;
    ungetc(c, in);
  }else{
    c = fgetc(in);
    while((c != '\"')
	  && (ptr < buf+size)){
      if(c != '\n'){ /* ignore line breaks */
	*ptr = c; ptr++;
      }
      c = fgetc(in);
    }
    *ptr = 0;
  }
  
  eat_line_trailing(in);

  DEBUG(6) fprintf(stderr, "rval = %s\n", buf);

  return TRUE;
}

static
gboolean read_statement(FILE *in,
			gchar *lval, gint lsize,
			gchar *rval, gint rsize)
{
  gint c;

  DEBUG(6) fprintf(stderr, "read_statement()\n");

  /* eat comments and empty lines: */
  if(!eat_comments(in)) return FALSE;

  DEBUG(6) fprintf(stderr, "read_statement() 1\n");

  if(read_lval(in, lval, lsize)){
    DEBUG(6) fprintf(stderr, "lval = %s\n", lval);
    if(c = fgetc(in) == '='){
      if(read_rval(in, rval, rsize)){
	DEBUG(6) fprintf(stderr, "rval = %s\n", rval);
	return TRUE;
      }
    }else{
      fprintf(stderr, "'=' expected after %s, char was '%c'\n", lval, c);
    }
  }
  return FALSE;
}

gboolean read_conf(gchar *filename)
{
  ssize_t len = 256;
  FILE *in;

  conf.run_as_user = FALSE;

  conf.use_syslog = FALSE;
  conf.log_max_pri = 7;
  conf.do_queue = FALSE;

  conf.alias_file = NULL;

  conf.local_nets = NULL;

  conf.local_net_routes = NULL;
  conf.connect_routes = NULL;

  conf.online_detect = NULL;
  conf.online_file = NULL;
  conf.mserver_iface = NULL;

  init_conf();

  if(in = fopen(filename, "r")){
    gchar lval[256], rval[2048];
    while(read_statement(in, lval, 256, rval, 2048)){
      if(strcmp(lval, "debug_level") == 0){
	if(conf.debug_level == -1)
	  conf.debug_level = atoi(rval);
      }
      else if(strcmp(lval, "run_as_user") == 0)
	conf.run_as_user = parse_boolean(rval);
      else if(strcmp(lval, "use_syslog") == 0)
	conf.use_syslog = parse_boolean(rval);
      else if(strcmp(lval, "mail_dir") == 0)
	conf.mail_dir = g_strdup(rval);
      else if(strcmp(lval, "spool_dir") == 0)
	conf.spool_dir = g_strdup(rval);
      else if(strcmp(lval, "log_dir") == 0)
	conf.log_dir = g_strdup(rval);
      else if(strcmp(lval, "host_name") == 0)
	conf.host_name = g_strdup(rval);
      else if(strcmp(lval, "remote_port") == 0)
	conf.remote_port = atoi(rval);
      else if(strcmp(lval, "local_hosts") == 0)
	conf.local_hosts = parse_list(rval, FALSE);
      else if(strcmp(lval, "local_nets") == 0)
	conf.local_nets = parse_list(rval, FALSE);
      else if(strcmp(lval, "alias_file") == 0){
	conf.alias_file = g_strdup(rval);
      }
      else if(strcmp(lval, "listen_addresses") == 0){
	GList *node;
	GList *tmp_list = parse_list(rval, FALSE);
	    
	conf.listen_addresses = NULL;
	foreach(tmp_list, node){
	  conf.listen_addresses =
	    g_list_append(conf.listen_addresses,
			  parse_interface((gchar *)(node->data), 25));
	  g_free(node->data);
	}
	g_list_free(tmp_list);
      }
      else if(strncmp(lval, "connect_route.", 14) == 0){
	connect_route *route = g_malloc(sizeof(connect_route));
	route->name = g_strdup(&(lval[14]));
	route->filename = g_strdup(rval);
	route->is_local_net = FALSE;
	conf.connect_routes = g_list_append(conf.connect_routes, route);
      }
      else if(strcmp(lval, "local_net_route") == 0){
	connect_route *route = create_local_route();
	route->filename = g_strdup(rval);
	if(read_route(route, TRUE))
	  conf.local_net_routes =
	    g_list_append(conf.local_net_routes, route);
	else{
	  g_free(route);
	}
      }
      else if(strcmp(lval, "online_detect") == 0)
	conf.online_detect = g_strdup(rval);
      else if(strcmp(lval, "online_file") == 0)
	conf.online_file = g_strdup(rval);
      else if(strcmp(lval, "mserver_iface") == 0)
	conf.mserver_iface = parse_interface(rval, 224);
      else if(strcmp(lval, "do_queue") == 0)
	conf.do_queue = parse_boolean(rval);
      else
	fprintf(stderr, "var '%s' not yet known, ignored\n", lval);
    }
    fclose(in);

    if(conf.local_net_routes == NULL)
      if(conf.local_nets != NULL)
	conf.local_net_routes = g_list_append(NULL, create_local_route());

    return TRUE;
  }else
    fprintf(stderr, "could not open config file %s: %s\n", filename, strerror(errno));
  return FALSE;
}

gboolean read_route(connect_route *route, gboolean is_local_net)
{
  gboolean ok = FALSE;
  FILE *in;
  ssize_t len = 256;

  route->is_local_net = is_local_net;

  route->mail_host = NULL;
  route->do_correct_helo = FALSE;
  route->allowed_mail_locals = NULL;
  route->allowed_rcpt_domains = NULL;
  route->not_allowed_rcpt_domains = NULL;

  route->set_h_from_domain = NULL;
  route->set_h_reply_to_domain = NULL;
  route->set_return_path_domain = NULL;

  route->map_h_from_addresses = NULL;
  route->map_h_reply_to_addresses = NULL;
  route->map_return_path_addresses = NULL;

  route->expand_h_sender_domain = TRUE;

  route->resolve_list = NULL;

  if(in = fopen(route->filename, "r")){
    gchar lval[256], rval[2048];
    while(read_statement(in, lval, 256, rval, 2048)){
      if(strcmp(lval, "mail_host") == 0)
	route->mail_host = g_strdup(rval);
      else if(strcmp(lval, "do_correct_helo") == 0)
	route->do_correct_helo = parse_boolean(rval);
      else if(strcmp(lval, "allowed_mail_locals") == 0)
	route->allowed_mail_locals = parse_list(rval, TRUE);
      else if(strcmp(lval, "not_allowed_mail_locals") == 0)
	route->not_allowed_mail_locals = parse_list(rval, TRUE);
      else if(strcmp(lval, "allowed_rcpt_domains") == 0)
	route->allowed_rcpt_domains = parse_list(rval, TRUE);
      else if(strcmp(lval, "not_allowed_rcpt_domains") == 0)
	route->not_allowed_rcpt_domains = parse_list(rval, TRUE);
      else if(strcmp(lval, "set_h_from_domain") == 0)
	route->set_h_from_domain = g_strdup(rval);
      else if(strcmp(lval, "set_h_reply_to_domain") == 0)
	route->set_h_reply_to_domain = g_strdup(rval);
      else if(strcmp(lval, "set_return_path_domain") == 0)
	route->set_return_path_domain = g_strdup(rval);
      else if(strcmp(lval, "map_return_path_addresses") == 0){
	GList *node, *list;

	list = parse_list(rval, TRUE);
	foreach(list, node){
	  gchar *item = (gchar *)(node->data);
	  table_pair *pair = parse_table_pair(item, ':');
	  address *adr = create_address((gchar *)(pair->value), TRUE);
	  g_free(pair->value);
	  pair->value = (gpointer *)adr;
	  route->map_return_path_addresses =
	    g_list_append(route->map_return_path_addresses, pair);
	  g_free(item);
	}
	g_list_free(list);
      }
      else if(strcmp(lval, "map_h_from_addresses") == 0){
	GList *list, *node;

	list = parse_list(rval, TRUE);
	foreach(list, node){
	  gchar *item = (gchar *)(node->data);
	  table_pair *pair = parse_table_pair(item, ':');
	  route->map_h_from_addresses = 
	    g_list_append(route->map_h_from_addresses, pair);
	  g_free(item);
	}
	g_list_free(list);
      }
      else if(strcmp(lval, "map_h_reply_to_addresses") == 0){
	GList *list, *node;

	list = parse_list(rval, TRUE);
	foreach(list, node){
	  gchar *item = (gchar *)(node->data);
	  table_pair *pair = parse_table_pair(item, ':');
	  route->map_h_reply_to_addresses = 
	    g_list_append(route->map_h_reply_to_addresses, pair);
	  g_free(item);
	}
	g_list_free(list);
      }
      else if(strcmp(lval, "expand_h_sender_domain") == 0){
	route->expand_h_sender_domain = parse_boolean(rval);	    
      }
    }

    if(route->resolve_list == NULL){
      if(is_local_net){
	route->resolve_list =
	  g_list_append(NULL, resolve_byname);
      }else{
	route->resolve_list =
	  g_list_append(route->resolve_list, resolve_dns_mx);
	route->resolve_list =
	  g_list_append(route->resolve_list, resolve_dns_a);
	route->resolve_list =
	  g_list_append(route->resolve_list, resolve_byname);
      }
    }
    fclose(in);
    ok = TRUE;
  }else{
    logwrite(LOG_ALERT, "could not open route file %s:",
	     route->filename, strerror(errno));
  }
  return ok;
}

connect_route *create_local_route()
{
  connect_route *route;

  route = g_malloc(sizeof(connect_route));
  if(route){
    memset(route, 0, sizeof(connect_route));
    route->is_local_net = TRUE;
    route->name = g_strdup("local route (default)");
    route->expand_h_sender_domain = TRUE;
    route->resolve_list =
      g_list_append(NULL, resolve_byname);
  }
  return route;
}
    
