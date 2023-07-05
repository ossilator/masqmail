/*  MasqMail
    Copyright (C) 2000-2002 Oliver Kurth

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
#include <sys/file.h>
#include <sys/types.h>

#include "masqmail.h"
#include "pop3_in.h"

#ifdef ENABLE_POP3

static int volatile sighup_seen = 0;

static
void sighup_handler(int sig)
{
  sighup_seen = 1;
  signal(SIGHUP, sighup_handler);
}

static
void sigchld_handler(int sig)
{
  pid_t pid;
  int status;
  
  pid = waitpid(0, &status, 0);
  if(pid > 0){
    if(WEXITSTATUS(status) != EXIT_SUCCESS)
      logwrite(LOG_WARNING, "process %d exited with %d\n",
	       pid, WEXITSTATUS(status));
    if(WIFSIGNALED(status))
      logwrite(LOG_WARNING,
	       "process with pid %d got signal: %d\n",
	       pid, WTERMSIG(status));
  }
  signal(SIGCHLD, sigchld_handler);
}

static
int get_lock(get_conf *gc)
{
#ifdef USE_DOTLOCK
  gboolean ok = FALSE;
  gchar *hitch_name;
  gchar *lock_name;

  /* the name of the lock is constructed from the user
     and the server name, to prevent more than one connection at the same time
     to the same server and the same user. This way concurrent connections
     are possible to different servers or different users */
  hitch_name = g_strdup_printf("%s/masqmail-get-%s@%s-%d.lock",
			       conf.lock_dir, gc->login_user,
			       gc->server_name, getpid());
  lock_name = g_strdup_printf("%s/masqmail-get-%s@%s.lock",
			      conf.lock_dir, gc->login_user, gc->server_name);
  
  ok = dot_lock(lock_name, hitch_name);
  if(!ok) logwrite(LOG_WARNING,
		   "getting mail for %s@%s is locked\n",
		   gc->login_user, gc->server_name);

  g_free(lock_name);
  g_free(hitch_name);

  return ok;
#else
  gchar *lock_name;
  int fd;

  lock_name = g_strdup_printf("%s/masqmail-get-%s@%s.lock",
			      conf.lock_dir, gc->login_user, gc->server_name);

  if((fd = open(lock_name, O_WRONLY|O_NDELAY|O_APPEND|O_CREAT, 0600)) >= 0){
    if(flock(fd, LOCK_EX|LOCK_NB) != 0){
      close(fd);
      logwrite(LOG_WARNING,
	       "getting mail for %s@%s is locked\n",
	       gc->login_user, gc->server_name);
      fd = -1;
    }
  }else
    logwrite(LOG_WARNING,
	     "could not open lock %s: %s\n", lock_name, strerror(errno));

  g_free(lock_name);

  return fd;
#endif
}

#ifdef USE_DOTLOCK
static
gboolean get_unlock(get_conf *gc)
{
  gchar *lock_name lock_name =
    g_strdup_printf("%s/masqmail-get-%s@%s.lock",
		    conf.lock_dir, gc->login_user, gc->server_name);
  
  dot_unlock(lock_name);

  g_free(lock_name);

  return TRUE;
}
#else
static void get_unlock(get_conf *gc, int fd)
{
  gchar *lock_name =
    g_strdup_printf("%s/masqmail-get-%s@%s.lock",
		    conf.lock_dir, gc->login_user, gc->server_name);

  flock(fd, LOCK_UN);
  close(fd);

  unlink(lock_name);
  g_free(lock_name);
}
#endif

gboolean get_from_file(gchar *fname)
{
  guint flags = 0;
  get_conf *gc = read_get_conf(fname);
  gboolean ok = TRUE;
  int lock;

  if(gc){
    if(!gc->do_keep) flags |= POP3_FLAG_DELETE;
    if(gc->do_uidl) flags |= POP3_FLAG_UIDL;
    if(gc->do_uidl_dele) flags |= POP3_FLAG_UIDL_DELE;
    
    if(!(gc->server_name)){
      logwrite(LOG_ALERT, "no server name given in %s\n", fname); return FALSE;
    }
    if(!(gc->address)){
      logwrite(LOG_ALERT, "no address given in %s\n", fname); return FALSE;
    }
    if(!(gc->login_user)){
      logwrite(LOG_ALERT, "no user name given in %s\n", fname); return FALSE;
    }
    if(!(gc->login_pass)){
      logwrite(LOG_ALERT, "no password given in %s\n", fname); return FALSE;
    }

    DEBUG(3) debugf("flags = %d\n", flags);
    
    if((strcmp(gc->protocol, "pop3") == 0) || (strcmp(gc->protocol, "apop") == 0)){
      pop3_base *popb = NULL;

      if(strcmp(gc->protocol, "apop") == 0){
	flags |= POP3_FLAG_APOP;
	DEBUG(3) debugf("attempting to get mail for user %s at host %s"
			" for %s@%s with apop\n",
			gc->login_user, gc->server_name,
			gc->address->local_part, gc->address->domain);
      }else{
	DEBUG(3) debugf("attempting to get mail for user %s at host %s"
			" for %s@%s with pop3\n",
			gc->login_user, gc->server_name,
			gc->address->local_part, gc->address->domain);
      }
#ifdef USE_DOTLOCK
      if((lock = get_lock(gc))){
#else
      if((lock = get_lock(gc)) >= 0){
#endif
	if(gc->wrapper){
	  popb = pop3_in_open_child(gc->wrapper, flags);
	  /* quick hack */
	  popb->remote_host = gc->server_name;
	}else{
	  popb = pop3_in_open(gc->server_name, gc->server_port,
			      gc->resolve_list, flags);
	}
	if(popb){
	  ok = pop3_get(popb, gc->login_user, gc->login_pass,
			gc->address, gc->return_path,
			gc->max_count, gc->max_size, gc->max_size_delete);
	  pop3_in_close(popb);
	}else{
	  ok = FALSE;
	  logwrite(LOG_ALERT, "failed to connect to host %s\n", gc->server_name);
	}
#ifdef USE_DOTLOCK
	get_unlock(gc);
#else
	get_unlock(gc, lock);
#endif
      }
    }else{
      logwrite(LOG_ALERT, "get protocol %s unknown\n", gc->protocol);
      ok = FALSE;
    }

    destroy_get_conf(gc);
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

void get_online()
{
  GList *gf_list = NULL;
  gchar *connect_name = detect_online();

  if(connect_name != NULL){
    void (*old_signal)(int);

    old_signal = signal(SIGCHLD, SIG_DFL);

    logwrite(LOG_NOTICE, "detected online configuration %s\n", connect_name);
    /* we are online! */
    gf_list = (GList *)table_find(conf.online_gets, connect_name);
    if(gf_list != NULL){
      GList *node;
      foreach(gf_list, node){
	gchar *fname = (gchar *)(node->data);
	pid_t pid;

	if(fname[0] != '/')
	  fname = (gchar *)table_find(conf.get_names, fname);

	if(fname != NULL){
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
      }
    }
    signal(SIGCHLD, old_signal);    
  }
}

void get_daemon(gint gival, char *argv[])
{
  struct timeval tm;
  time_t time_before, time_now;
  int sel_ret;

  /* setup handler for HUP signal: */
  signal(SIGHUP, sighup_handler);

  /* we can give up root privileges */
  if(!conf.run_as_user){
    if(setegid(conf.mail_gid) != 0){
      logwrite(LOG_ALERT, "could not change gid to %d: %s\n",
	       conf.mail_gid, strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(seteuid(conf.mail_uid) != 0){
      logwrite(LOG_ALERT, "could not change uid to %d: %s\n",
	       conf.mail_uid, strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  /*  sel_ret = 0;*/
  time(&time_before);
  time_before -= gival;
  sel_ret = -1;

  while (1){
    /* see listen_port() in listen.c */
    if(gival > 0){
      time(&time_now);
      if(sel_ret == 0){ /* we are either just starting or did a queue run */
	tm.tv_sec = gival;
	tm.tv_usec = 0;
	time_before = time_now;
      }else{
	tm.tv_sec = gival - (time_now - time_before);
	tm.tv_usec = 0;

	/* race condition, very unlikely (but possible): */
	if(tm.tv_sec < 0)
	  tm.tv_sec = 0;
      }
    }

    if ((sel_ret = select(0, NULL, NULL, NULL, &tm)) < 0){
      if(errno != EINTR){
	logwrite(LOG_ALERT, "select: (terminating): %s\n", strerror(errno));
	exit (EXIT_FAILURE);
      }else{
	if(sighup_seen){
	  logwrite(LOG_NOTICE, "HUP signal received. Restarting daemon\n");

	  if(argv == NULL) exit(EXIT_SUCCESS);

	  execv(argv[0], &(argv[0]));
	  logwrite(LOG_ALERT, "restarting failed: %s\n", strerror(errno));
	  exit(EXIT_FAILURE);

	}
      }
    }else{
      /* If select returns 0, the interval time has elapsed.
	 We start a new get process */
      int pid;
      signal(SIGCHLD, sigchld_handler);
      if((pid = fork()) == 0){
	get_online();

	_exit(EXIT_SUCCESS);
      }
      else if(pid < 0){
	logwrite(LOG_ALERT, "could not fork for get run");
      }
    }
  }
}

gboolean pop_before_smtp(gchar *fname)
{
  gboolean ok = FALSE;
  GList *resolve_list = NULL;
  get_conf *gc = read_get_conf(fname);
  guint flags = 0;

#ifdef ENABLE_RESOLVER
  resolve_list = g_list_append(resolve_list, resolve_dns_a);
#endif
  resolve_list = g_list_append(resolve_list, resolve_byname);

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
