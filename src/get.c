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

#include <sys/wait.h>

#include "masqmail.h"
#include "pop3_in.h"

#ifdef ENABLE_POP3

gboolean get_from_file(gchar *fname)
{
  guint flags = 0;
  get_conf *gc = read_get_conf(fname);
  gboolean ok = TRUE;

  if(gc){
    if(!gc->do_keep) flags |= POP3_FLAG_DELETE;
    if(gc->do_uidl) flags |= POP3_FLAG_UIDL;
    
    if(!(gc->server_name)) { logwrite(LOG_ALERT, "no server name given in %s\n", fname); return FALSE; }
    if(!(gc->address)) { logwrite(LOG_ALERT, "no address given in %s\n", fname); return FALSE; }
    if(!(gc->login_user)) { logwrite(LOG_ALERT, "no user name given in %s\n", fname); return FALSE; }
    if(!(gc->login_pass)) { logwrite(LOG_ALERT, "no password given in %s\n", fname); return FALSE; }

    DEBUG(3) debugf("flags = %d\n", flags);
    
    if((strcmp(gc->protocol, "pop3") == 0) || (strcmp(gc->protocol, "apop") == 0)){
      pop3_base *popb = NULL;

      if(strcmp(gc->protocol, "apop") == 0){
	flags |= POP3_FLAG_APOP;
	DEBUG(3) debugf("attempting to get mail for user %s at host %s for %s@%s with apop\n",
			gc->login_user, gc->server_name, gc->address->local_part, gc->address->domain);
      }else{
	DEBUG(3) debugf("attempting to get mail for user %s at host %s for %s@%s with pop3\n",
			gc->login_user, gc->server_name, gc->address->local_part, gc->address->domain);
      }

      if(gc->wrapper){
	popb = pop3_in_open_child(gc->wrapper, flags);
	/* quick hack */
	popb->remote_host = gc->server_name;
      }else{
	popb = pop3_in_open(gc->server_name, gc->server_port, gc->resolve_list, flags);
      }
      if(popb){
	ok = pop3_get(popb, gc->login_user, gc->login_pass, gc->address, gc->max_size);
	pop3_in_close(popb);
      }else{
	ok = FALSE;
	logwrite(LOG_ALERT, "failed to connect to host %s\n", gc->server_name);
      }
    }else{
      logwrite(LOG_ALERT, "get protocol %s unknown\n", gc->protocol);
      ok = FALSE;
    }
  }
  return ok;
}

gboolean get_from_name(gchar *name)
{
  gchar *fname = (gchar *)table_find(conf.get_names, name);
  if(fname)
    return get_from_file(fname);
  return FALSE;
}

gboolean get_all()
{
  GList *get_table = conf.get_names;
  GList *get_node;
  void (*old_signal)(int);

  old_signal = signal(SIGCHLD, SIG_DFL);

  foreach(get_table, get_node){
    table_pair *pair = (table_pair *)(get_node->data);
    gchar *fname = (gchar *)pair->value;
    pid_t pid;

    pid = fork();
    if(pid == 0){
      signal(SIGCHLD, old_signal);    
      exit(get_from_file(fname) ? EXIT_SUCCESS : EXIT_FAILURE);
    }else if(pid > 0){
      int status;
      waitpid(pid, &status, 0);
      if(WEXITSTATUS(status) != EXIT_SUCCESS)
	logwrite(LOG_WARNING, "child returned %d\n", WEXITSTATUS(status));
      if(WIFSIGNALED(status))
	logwrite(LOG_WARNING, "child got signal: %d\n", WTERMSIG(status));
    }else
      logwrite(LOG_WARNING, "forking child failed: %s\n", strerror(errno));
  }
    
  signal(SIGCHLD, old_signal);    

  return TRUE;
}

gboolean pop_before_smtp(gchar *fname)
{
  gboolean ok = FALSE;
  GList *resolve_list =
    g_list_append(NULL, resolve_dns_a);

  get_conf *gc = read_get_conf(fname);
  guint flags = 0;
  if(strcmp(gc->protocol, "pop3") == 0){
    DEBUG(3) debugf("attempting to login for user %s, host = %s with pop3\n",
		    gc->login_user, gc->server_name);
    ok = pop3_login(gc->server_name, gc->server_port, resolve_list,
		    gc->login_user, gc->login_pass,
		    flags);
  }else if(strcmp(gc->protocol, "apop") == 0){
    DEBUG(3) debugf("attempting to login for user %s, host = %s with apop\n",
		    gc->login_user, gc->server_name);
    ok = pop3_login(gc->server_name, gc->server_port, resolve_list,
		    gc->login_user, gc->login_pass,
		    flags | POP3_FLAG_APOP);
  }else{
    logwrite(LOG_ALERT, "get protocol %s unknown\n", gc->protocol);
  }
  return ok;
}

#endif
