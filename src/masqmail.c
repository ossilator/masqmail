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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include <glib.h>

#include "masqmail.h"

/* is there really no function in libc for this? */
gboolean is_ingroup(uid_t uid, gid_t gid)
{
  struct group *grent = getgrgid(gid);

  if(grent){
    struct passwd *pwent = getpwuid(uid);
    if(pwent){
      char *entry;
      int i = 0;
      while(entry = grent->gr_mem[i++]){
	if(strcmp(pwent->pw_name, entry) == 0)
	  return TRUE;
      }
    }
  }
  return FALSE;
}

gint time_interval(gchar *str)
{
  gchar buf[16];
  gchar *p = str, *q = buf;
  gint factor = 1, val;

  while(*p && isdigit(*p)) *(q++) = *(p++);
  *q = 0;
  val = atoi(buf);
  
  switch(*p){
  case 'w':
    factor *= 7;
  case 'd':
    factor *=24;
  case 'h':
    factor *= 60;
  case 'm':
    factor *= 60;
  case 's':
    break;
  default:
    return -1;
  }
  return val * factor;
}

gchar *get_optarg(char *argv[], gint argc, gint *argp, gint *pos)
{
  if(argv[*argp][*pos])
    return &(argv[*argp][*pos]);
  else{
    if(*argp+1 < argc){
      if(argv[(*argp)+1][0] != '-'){
	(*argp)++;
	*pos = 0;
	return &(argv[*argp][*pos]);
      }
    }
  }
  return NULL;
}  

gchar *get_progname(gchar *arg0)
{
  gchar *p = arg0 + strlen(arg0) - 1;
  while(p > arg0){
    if(*p == '/')
      return p+1;
    p--;
  }
  return p;
}

int
main(int argc, char *argv[])
{
  guint pid;

  /* cmd line flags */
  guint port = 2525;
  gchar *conf_file = "/etc/masqmail.conf";
  gint arg = 1;
  gboolean do_listen = FALSE;
  gboolean do_stdin_smtp = FALSE;
  gboolean do_runq = FALSE;
  gint queue_interval = 0;
  gboolean do_runq_connected = FALSE;
  gboolean opt_t = FALSE;
  gboolean opt_i = FALSE;
  gboolean opt_odb = FALSE;
  gboolean opt_oem = FALSE;
  gboolean do_queue = FALSE;
  gboolean do_list_queue = FALSE;
  gboolean exit_failure = FALSE;
  gchar *route_name = NULL;
  gchar *progname;
  uid_t uid;
  gid_t gid;

  progname = get_progname(argv[0]);

  if(strcmp(progname, "mailq") == 0)
    do_list_queue = TRUE;

  uid = getuid();
  gid = getgid();

  conf.debug_level = -1;

  /* parse cmd line */
  while(arg < argc){
    gint pos = 0;
    if((argv[arg][pos] == '-') && (argv[arg][pos+1] != '-')){
      pos++;
      switch(argv[arg][pos++]){
      case 'b':
	switch(argv[arg][pos++]){
	case 'd':
	  do_listen = TRUE;
	  break;
	case 'i':
	  /* ignored */
	  break;
	case 's':
	  do_stdin_smtp = TRUE;
	  break;
	case 'p':
	  do_list_queue = TRUE;
	  break;
	default:
	  fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
	  exit(EXIT_FAILURE);
	}
	break;
      case 'B':
	/* we ignore this and throw the argument away */
	get_optarg(argv, argc, &arg, &pos);
	break;
      case 'C':
	if(!(conf_file = get_optarg(argv, argc, &arg, &pos))){
	  fprintf(stderr, "-C requires a filename as argument.\n");
	  exit(EXIT_FAILURE);
	}
	break;

      case 'd':
	{
	  gchar *optarg = get_optarg(argv, argc, &arg, &pos);
	  if(optarg)
	    conf.debug_level = atoi(optarg);
	  else
	    conf.debug_level++;
	}
	break;
      case 'i':
	if(argv[arg][pos] == 0){
	  opt_i = TRUE;
	  exit_failure = FALSE; /* may override -oem */
	}else{
	  fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
	  exit(EXIT_FAILURE);
	}
	break;
      case 'o':
	switch(argv[arg][pos++]){
	case 'e':
	  if(argv[arg][pos++] == 'm') /* -oem */
	    if(!opt_i) exit_failure = TRUE;
	    opt_oem = TRUE;
	  break;
	case 'd':
	  if(argv[arg][pos] == 'b') /* -odb */
	    opt_odb = TRUE;
	  else if(argv[arg][pos] == 'q') /* -odq */
	    do_queue = TRUE;
	  break;
	case 'i':
	  opt_i = TRUE;
	  exit_failure = FALSE; /* may override -oem */
	  break;
	}
	break;

      case 'q':
	{
	  gchar *optarg;

	  do_runq = TRUE;
	  if(argv[arg][pos] == 'o'){
	    pos++;
	    if((route_name = get_optarg(argv, argc, &arg, &pos)) == NULL){
	       fprintf(stderr,
		       "-qo requires a connection name  as argument.\n");
	       exit(EXIT_FAILURE);
	    }
	  }else if(optarg = get_optarg(argv, argc, &arg, &pos)){
	    queue_interval = time_interval(optarg);
	  }
	}
	break;
      case 't':
	if(argv[arg][pos] == 0){
	  opt_t = TRUE;
	}else{
	  fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
	  exit(EXIT_FAILURE);
	}
	break;
      default:
	fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
	exit(EXIT_FAILURE);
      }
    }else{
      if(argv[arg][pos+1] == '-'){
        if(argv[arg][pos+2] != '\0'){
	  fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
	  exit(EXIT_FAILURE);
        }
	arg++;
      }
      break;
    }
    arg++;
  }

  /* initialize random generator */
  srand(time(NULL));

  if(!read_conf(conf_file)) exit(EXIT_FAILURE);

  if(do_queue) conf.do_queue = TRUE;

  if(!conf.run_as_user){
    DEBUG(5) fprintf(stderr, "setting real user and group\n");
    if(setgid(0) != 0){
      fprintf(stderr,
	      "could not set gid to 0. Is the setuid bit set? : %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }
    if(setuid(0) != 0){
      fprintf(stderr,
	      "could not gain root privileges. Is the setuid bit set? : %s\n",
	      strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  if(!logopen()) exit(EXIT_FAILURE);

  DEBUG(5){
    gchar **str = argv;
    debugf("args: \n");
    while(*str){
      debugf("%s \n", *str);
      str++;
    }
  }
  DEBUG(5) debugf("queue_interval = %d\n", queue_interval);

  if(do_listen || (do_runq && queue_interval > 0)){

    /* daemon */
    if(!conf.run_as_user){
      if((uid != 0) && (uid != conf.mail_uid)){
	fprintf(stderr, "must be root or %s for daemon.\n", DEF_MAIL_USER);
	exit(EXIT_FAILURE);
      }
    }

    if((pid = fork()) > 0){
      exit(EXIT_SUCCESS);
    }else if(pid < 0){
      logwrite(LOG_ALERT, "could not fork!");
      exit(EXIT_FAILURE);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    listen_port(port, do_listen ? conf.listen_addresses : NULL,
		queue_interval, argv);

  }else if(do_runq){

    /* queue runs */
    if(!conf.run_as_user){
      if((uid != 0) && (uid != conf.mail_uid) && (!is_ingroup(uid, conf.mail_gid))){
	fprintf(stderr,
		"must be in group root or %s for queue run.\n",
		DEF_MAIL_GROUP);
	exit(EXIT_FAILURE);
      }

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
      
    if(route_name == NULL)
      queue_run();
    else{
      connect_route *route = NULL;

      route = find_route(conf.connect_routes, route_name);

      if(route != NULL){
	if(read_route(route, FALSE)){
	  conf.curr_route = route;
	  run_route_queue(route);
	  conf.curr_route = NULL;
	}
	else
	  fprintf(stderr, "could not read route file '%s'\n", route->filename);
      }else{
	fprintf(stderr, "route with name '%s' not found.\n", route_name);
	exit(EXIT_FAILURE);
      }
    }
  }else if(do_stdin_smtp){

    /* accept smtp message on stdin */
    /* write responses to stderr.
       pine seems to expect responses on stderr,
       do not ask me why. I tried stdout, but then pine waits forever.
    */

    struct sockaddr_in saddr;
    gchar *peername = NULL;
    int dummy = sizeof(saddr);

    if(!conf.run_as_user){
      seteuid(uid);
      setegid(gid);
    }

    DEBUG(5) debugf("accepting smtp message on stdin\n");

    if(getpeername(0, &saddr, &dummy) == 0)
      peername = g_strdup(inet_ntoa(saddr.sin_addr));
    else if(errno != ENOTSOCK)
      exit(EXIT_FAILURE);

    //smtp_in(stdin, stdout, peername);
    smtp_in(stdin, stderr, peername);

  }else if(do_list_queue){

    queue_list();

  }else{

    /* accept message on stdin */
    accept_error err;
    message *msg = create_message();

    if(!conf.run_as_user){
      seteuid(uid);
      setegid(gid);
    }

    DEBUG(5) debugf("accepting message on stdin\n");

    msg->received_prot = PROT_LOCAL;
    for(; arg < argc; arg++){
      if(argv[arg][0] != '|')
	msg->rcpt_list =
	  g_list_append(msg->rcpt_list,
			create_address_qualified(argv[arg], TRUE, conf.host_name));
      else{
	logwrite(LOG_ALERT, "no pipe allowed as recipient address: %s\n", argv[arg]);
	exit(EXIT_FAILURE);
      }
    }

    if((err =
	accept_message(stdin, msg,
		       (opt_t ? ACC_DEL_RCPTS|ACC_DEL_BCC|ACC_RCPT_FROM_HEAD
			: ACC_HEAD_FROM_RCPT)|
		       (opt_i ? ACC_NODOT_TERM : 0)))
       == AERR_OK){
      if(spool_write(msg, TRUE)){
	pid_t pid;
	logwrite(LOG_NOTICE, "%s <= <%s@%s> with %s\n",
		 msg->uid, msg->return_path->local_part,
		 msg->return_path->domain, prot_names[PROT_LOCAL]);

	if(!conf.do_queue){
	  if((pid = fork()) == 0){
	    if(deliver(msg))
	      exit(EXIT_SUCCESS);
	    else
	      exit(EXIT_FAILURE);
	  }else if(pid < 0){
	    logwrite(LOG_ALERT, "could not fork for delivery, id = %s",
		     msg->uid);
	  }
	}
      }else{
	fprintf(stderr, "Could not write spool file\n");
	exit(EXIT_FAILURE);
      }
    }else{
      switch(err){
      case AERR_EOF:
	fprintf(stderr, "unexpceted EOF.\n");
	exit(EXIT_FAILURE);
      default:
	/* should never happen: */
	fprintf(stderr, "Unknown error\r\n");
	return;
      }
      exit(EXIT_FAILURE);
    }
    exit(exit_failure ? EXIT_FAILURE : EXIT_SUCCESS);
  }
  logclose();
}
