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

#include <glib.h>

#include "masqmail.h"

/* mutually exclusive modes. Note that there is neither a 'get' mode
   nor a 'queue daemon' mode. These, as well as the distinction beween
   the two (non exclusive) daemon (queue and listen) modes are handled
   by flags.*/
typedef enum _mta_mode
{
  MODE_ACCEPT = 0, /* accept message on stdin */
  MODE_DAEMON,     /* run as daemon */
  MODE_RUNQUEUE,   /* single queue run, online or offline */
  MODE_SMTP,       /* accept SMTP on stdin */
  MODE_LIST,       /* list queue */
  MODE_MCMD,       /* do queue manipulation */
  MODE_VERSION,    /* show version */
  MODE_BI,         /* fake ;-) */
  MODE_NONE        /* to prevent default MODE_ACCEPT */    
}mta_mode;

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

static
gboolean is_in_netlist(gchar *host, GList *netlist)
{
  guint hostip = inet_addr(host);
  struct in_addr addr;

  addr.s_addr = hostip;
  if(addr.s_addr != INADDR_NONE){
    GList *node;
    foreach(netlist, node){
      struct in_addr *net = (struct in_addr *)(node->data);
      if((addr.s_addr & net->s_addr) == net->s_addr)
	return TRUE;
    }
  }
  return FALSE;
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

static
void mode_daemon(gboolean do_listen, gint queue_interval, char *argv[])
{
  guint pid;

  /* daemon */
  if(!conf.run_as_user){
    if((conf.orig_uid != 0) && (conf.orig_uid != conf.mail_uid)){
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

  listen_port(do_listen ? conf.listen_addresses : NULL,
	      queue_interval, argv);
}

static void mode_smtp()
{
  /* accept smtp message on stdin */
  /* write responses to stderr. */

  struct sockaddr_in saddr;
  gchar *peername = NULL;
  int dummy = sizeof(saddr);
  gchar *ident = NULL;

  if(!conf.run_as_user){
    seteuid(conf.orig_uid);
    setegid(conf.orig_gid);
  }

  DEBUG(5) debugf("accepting smtp message on stdin\n");

  if(getpeername(0, &saddr, &dummy) == 0){
    peername = g_strdup(inet_ntoa(saddr.sin_addr));
#ifdef ENABLE_IDENT
    {
      gchar *id = NULL;
      if((id = (gchar *)ident_id(0, 60))){
	ident = g_strdup(id);
      }
    }
#endif
  }else if(errno != ENOTSOCK)
    exit(EXIT_FAILURE);

  //smtp_in(stdin, stdout, peername);
  smtp_in(stdin, stderr, peername, NULL);

#ifdef ENABLE_IDENT
  if(ident) g_free(ident);
#endif
}

static void mode_accept(address *return_path, gchar *full_sender_name, guint accept_flags, char **addresses, int adr_cnt)
{
  /* accept message on stdin */
  accept_error err;
  message *msg = create_message();
  gint i;

  if(return_path != NULL){
    if((conf.orig_uid != 0) && (conf.orig_uid != conf.mail_uid) && (!is_ingroup(conf.orig_uid, conf.mail_gid))){
      fprintf(stderr,
	      "must be root, %s, or in group %s for setting return path.\n",
	      DEF_MAIL_USER, DEF_MAIL_GROUP);
      exit(EXIT_FAILURE);
    }
  }

  if(!conf.run_as_user){
    seteuid(conf.orig_uid);
    setegid(conf.orig_gid);
  }

  DEBUG(5) debugf("accepting message on stdin\n");

  msg->received_prot = PROT_LOCAL;
  for(i = 0; i < adr_cnt; i++){
    if(addresses[i][0] != '|')
      msg->rcpt_list =
	g_list_append(msg->rcpt_list,
		      create_address_qualified(addresses[i], TRUE, conf.host_name));
    else{
      logwrite(LOG_ALERT, "no pipe allowed as recipient address: %s\n", addresses[i]);
      exit(EXIT_FAILURE);
    }
  }

  /* -f option */
  msg->return_path = return_path;

  /* -F option */
  msg->full_sender_name = full_sender_name;
    
  if((err = accept_message(stdin, msg, accept_flags)) == AERR_OK){
    if(spool_write(msg, TRUE)){
      pid_t pid;
      logwrite(LOG_NOTICE, "%s <= <%s@%s> with %s\n",
	       msg->uid, msg->return_path->local_part,
	       msg->return_path->domain, prot_names[PROT_LOCAL]);

      if(!conf.do_queue){

	if((pid = fork()) == 0){

	  fclose(stdin);
	  fclose(stdout);
	  fclose(stderr);

	  if(deliver(msg)){
	    exit(EXIT_SUCCESS);
	  }else
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
      fprintf(stderr, "unexpected EOF.\n");
      exit(EXIT_FAILURE);
    default:
      /* should never happen: */
      fprintf(stderr, "Unknown error (%d)\r\n", err);
      exit(EXIT_FAILURE);
    }
    exit(EXIT_FAILURE);
  }
}

int
main(int argc, char *argv[])
{
  /* cmd line flags */
  gchar *conf_file = CONF_FILE;
  gint arg = 1;
  gboolean do_get = FALSE;

  gboolean do_listen = FALSE;
  gboolean do_runq = FALSE;
  gboolean do_runq_online = FALSE;

  gboolean do_queue = FALSE;

  mta_mode mta_mode = MODE_ACCEPT;

  gint queue_interval = 0;
  gboolean opt_t = FALSE;
  gboolean opt_i = FALSE;
  gboolean opt_odb = FALSE;
  gboolean opt_oem = FALSE;
  gboolean exit_failure = FALSE;

  gchar *M_cmd = NULL;

  gint exit_code = EXIT_SUCCESS;
  gchar *route_name = NULL;
  gchar *get_name = NULL;
  gchar *progname;
  gchar *f_address = NULL;
  gchar *full_sender_name = NULL;
  address *return_path = NULL; /* may be changed by -f option */

  progname = get_progname(argv[0]);

  if(strcmp(progname, "mailq") == 0)
    { mta_mode = MODE_LIST; }
  else if(strcmp(progname, "runq") == 0)
    { mta_mode = MODE_RUNQUEUE; do_runq = TRUE; }
  else if(strcmp(progname, "rmail") == 0)
    { mta_mode = MODE_ACCEPT; opt_i = TRUE; }
  else if(strcmp(progname, "smtpd") == 0 || strcmp(progname, "in.smtpd") == 0)
    { mta_mode = MODE_SMTP; }

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
	  mta_mode = MODE_DAEMON;
	  break;
	case 'i':
	  /* ignored */
	  mta_mode = MODE_BI;
	  break;
	case 's':
	  mta_mode = MODE_SMTP;
	  break;
	case 'p':
	  mta_mode = MODE_LIST;
	  break;
	case 'V':
	  mta_mode = MODE_VERSION;
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
      case 'F':
	{
	  full_sender_name = get_optarg(argv, argc, &arg, &pos);
	  if(!full_sender_name){
	    fprintf(stderr, "-F requires a name as an argument\n");
	    exit(EXIT_FAILURE);
	  }
	}
	break;
      case 'd':
	if(getuid() == 0){
	  char *lvl = get_optarg(argv, argc, &arg, &pos);
	  if(lvl)
	    conf.debug_level = atoi(lvl);
	  else{
	    fprintf(stderr, "-d requires a number as an argument.\n");
	    exit(EXIT_FAILURE);
	  }
	}else{
	  fprintf(stderr, "only root may set the debug level.\n");
	  exit(EXIT_FAILURE);
	}
	break;
      case 'f':
	/* set return path */
	{
	  gchar *address;
	  address = get_optarg(argv, argc, &arg, &pos);
	  if(address){
	    f_address = g_strdup(address);
	  }else{
	    fprintf(stderr, "-f requires an address as an argument\n");
	    exit(EXIT_FAILURE);
	  }
	}
	break;
      case 'g':
	do_get = TRUE;
	if(!mta_mode) mta_mode = MODE_NONE; /* to prevent default MODE_ACCEPT */
	if((optarg = get_optarg(argv, argc, &arg, &pos))){
	  get_name = get_optarg(argv, argc, &arg, &pos);
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
      case 'M':
	{
	  mta_mode = MODE_MCMD;
	  M_cmd = g_strdup(&(argv[arg][pos]));
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
	  mta_mode = MODE_RUNQUEUE;
	  if(argv[arg][pos] == 'o'){
	    pos++;
	    do_runq = FALSE;
	    do_runq_online = TRUE;
	    /* can be NULL, then we use online detection method */
	    route_name = get_optarg(argv, argc, &arg, &pos);
	  }else if((optarg = get_optarg(argv, argc, &arg, &pos))){
	    mta_mode = MODE_DAEMON;
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
      case 'v':
	break; /* currently ignored */
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

  if(mta_mode == MODE_VERSION){
    gchar *with_pop3 = "", *with_auth = "", *with_ident = "";
    
#ifdef ENABLE_POP3
    with_pop3 = " +pop3";
#endif
#ifdef ENABLE_AUTH
    with_auth = " +auth";
#endif
#ifdef ENABLE_IDENT
    with_ident = " +ident";
#endif

    printf("%s %s%s%s%s\n", PACKAGE, VERSION, with_pop3, with_auth, with_ident);
      
    exit(EXIT_SUCCESS);
  }

  /* initialize random generator */
  srand(time(NULL));

  /* close all possibly open file descriptors */
  {
    int i, max_fd = sysconf(_SC_OPEN_MAX);

    if(max_fd <= 0) max_fd = 64;
    for(i = 3; i < max_fd; i++)
      close(i);
  }

  read_conf(conf_file);
  if(do_queue) conf.do_queue = TRUE;

  /* if we are not privileged, and the config file was changed we
     implicetely set the the run_as_user flag and give up all
     privileges.

     So it is possible for a user to run his own daemon without
     breaking security.
  */
  if(strcmp(conf_file, CONF_FILE) != 0){
    if(conf.orig_uid != 0){
      conf.run_as_user = TRUE;
      seteuid(conf.orig_uid);
      setegid(conf.orig_gid);
      setuid(conf.orig_uid);
      setgid(conf.orig_gid);
    }
  }

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

  if(!logopen()){
    fprintf(stderr, "could not open log file\n");
    exit(EXIT_FAILURE);
  }

  DEBUG(1) debugf("masqmail %s starting\n", VERSION);

  DEBUG(5){
    gchar **str = argv;
    debugf("args: \n");
    while(*str){
      debugf("%s \n", *str);
      str++;
    }
  }
  DEBUG(5) debugf("queue_interval = %d\n", queue_interval);

  if(f_address){
    return_path = create_address_qualified(f_address, TRUE, conf.host_name);
    g_free(f_address);
    if(!return_path){
      fprintf(stderr, "invalid RFC821 address: %s\n", f_address);
      exit(EXIT_FAILURE);
    }
  }

  if(do_get){
#ifdef ENABLE_POP3
    if((mta_mode == MODE_NONE) || (mta_mode == MODE_RUNQUEUE)){

      set_identity(conf.orig_uid, "getting mail");

      if(get_name)
	get_from_name(get_name);
      else
	get_all();
    }else{
      logwrite(LOG_ALERT, "get (-g) only allowed alone or together with queue run (-q)\n");
    }
#else
    fprintf(stderr, "get (pop) support not compiled in\n");
#endif
  }

  switch(mta_mode){
  case MODE_DAEMON:
    mode_daemon(do_listen, queue_interval, argv);
    break;
  case MODE_RUNQUEUE:
    {
      /* queue runs */
      set_identity(conf.orig_uid, "queue run");

      if(do_runq)
	exit_code = queue_run() ? EXIT_SUCCESS : EXIT_FAILURE;

      if(do_runq_online){
	if(route_name != NULL){
	  conf.online_detect = g_strdup("argument");
	  set_online_name(route_name);
	}
	exit_code = queue_run_online() ? EXIT_SUCCESS : EXIT_FAILURE;
      }
    }
    break;
  case MODE_SMTP:

    mode_smtp();
    break;

  case MODE_LIST:

    queue_list();
    break;

  case MODE_BI:
    
    exit(EXIT_SUCCESS);
    break; /* well... */
    
  case MODE_MCMD:
    if(strcmp(M_cmd, "rm") == 0){
      gboolean ok = FALSE;

      set_euidgid(conf.mail_uid, conf.mail_gid, NULL, NULL);

      if(is_privileged_user(conf.orig_uid)){
	for(; arg < argc; arg++){
	  if(queue_delete(argv[arg]))
	    ok = TRUE;
	}
      }else{
	struct passwd *pw = getpwuid(conf.orig_uid);
	if(pw){
	  for(; arg < argc; arg++){
	    message *msg = msg_spool_read(argv[arg], FALSE);
#ifdef ENABLE_IDENT
	    if(((msg->received_host == NULL) && (msg->received_prot == PROT_LOCAL)) ||
	       is_in_netlist(msg->received_host, conf.ident_trusted_nets)){
#else
	      if((msg->received_host == NULL) && (msg->received_prot == PROT_LOCAL)){
#endif
	      if(msg->ident){
		if(strcmp(pw->pw_name, msg->ident) == 0){
		  if(queue_delete(argv[arg]))
		    ok = TRUE;
		}else{
		  fprintf(stderr, "you do not own message id %s\n", argv[arg]);
		}
	      }else
		fprintf(stderr, "message %s does not have an ident.\n", argv[arg]);
	    }else{
	      fprintf(stderr, "message %s was not received locally or from a trusted network.\n", argv[arg]);
	    }
	  }
	}else{
	  fprintf(stderr, "could not find a passwd entry for uid %d: %s\n", conf.orig_uid, strerror(errno));
	}
      }
      exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
    }else{
      fprintf(stderr, "unknown command %s\n", M_cmd);
      exit(EXIT_FAILURE);
    }
    break;

  case MODE_ACCEPT:
    {
      guint accept_flags =
	(opt_t ? ACC_DEL_RCPTS|ACC_DEL_BCC|ACC_RCPT_FROM_HEAD : ACC_HEAD_FROM_RCPT) |
	(opt_i ? ACC_NODOT_TERM : ACC_NODOT_RELAX);
    
      mode_accept(return_path, full_sender_name, accept_flags, &(argv[arg]), argc - arg);

      exit(exit_failure ? EXIT_FAILURE : EXIT_SUCCESS);
    }
    break;
  default:
    break;
  }

  logclose();

  exit(exit_code);
}
