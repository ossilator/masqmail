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

int volatile sighup_seen = 0;

static
void sighup_handler(int sig)
{
  sighup_seen = 1;
  signal(SIGHUP, sighup_handler);
}

int make_socket (unsigned short port, const char *address)
{
  int sock;
  struct sockaddr_in server;
  struct hostent *hp;
        
  /* Create the socket. */
  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (sock < 0){
    logwrite(LOG_ALERT, "socket: (terminating): %s\n", strerror(errno));
    exit (EXIT_FAILURE);
  }
        
  /* get address */
  if ((hp = gethostbyname(address)) == NULL) {
    logwrite(LOG_ALERT, "local address '%s' unknown. (terminating)\n", address);
    exit(EXIT_FAILURE);
  }
  memcpy(&server.sin_addr, hp->h_addr, hp->h_length);

  /* bind the socket */
  server.sin_family = AF_INET;
  server.sin_port = htons (port);
  if (bind (sock, (struct sockaddr *) &server, sizeof (server)) < 0){
    logwrite(LOG_ALERT, "bind: (terminating): %s\n", strerror(errno));
    exit (EXIT_FAILURE);
  }
        
  return sock;
}

void accept_connect(int listen_sock, int sock, struct sockaddr_in* sock_addr)
{
  pid_t pid;
  int dup_sock = dup(sock);
  FILE *out, *in;
  gchar *rem_host;

  rem_host = g_strdup(inet_ntoa(sock_addr->sin_addr));
  logwrite(LOG_NOTICE, "connect from host %s, port %hd\n",
	 rem_host,
	 ntohs (sock_addr->sin_port));

  // start child for connection:
  signal(SIGCHLD, SIG_IGN);
  pid = fork();
  if(pid == 0){
    close(listen_sock);
    out = fdopen(sock, "w");
    in = fdopen(dup_sock, "r");
    
    smtp_in(in, out, rem_host);

    exit(EXIT_SUCCESS);
  }else if(pid < 0){
    logwrite(LOG_WARNING, "could not fork for incoming smtp connection: %s\n",
	     strerror(errno));
  }
  //  fclose(out);
  //  fclose(in);
  close(sock);
  close(dup_sock);
}

void listen_port(int port, GList *iface_list, gint qival, char *argv[])
{
  int i;
  fd_set active_fd_set, read_fd_set;
  struct timeval tm;
  time_t time_before, time_now;
  struct sockaddr_in clientname;
  size_t size;
  GList *node;
  int sel_ret;

  /* Create the sockets and set them up to accept connections. */
  FD_ZERO (&active_fd_set);
  for(node = g_list_first(iface_list);
      node;
      node = g_list_next(node)){
    interface *iface = (interface *)(node->data);
    int sock;
    sock = make_socket (iface->port, iface->address);
    if (listen (sock, 1) < 0){
      logwrite(LOG_ALERT, "listen: (terminating): %s\n", strerror(errno));
      exit (EXIT_FAILURE);
    }
    logwrite(LOG_NOTICE, "listening on interface %s:%d\n",
	     iface->address, iface->port);
    FD_SET (sock, &active_fd_set);
  }
        
  /* setup handler for HUP signal: */
  signal(SIGHUP, sighup_handler);

  /* now that we have our socket(s),
     we can give up root privileges */
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

  sel_ret = 0;
  while (1){

    /* if we were interrupted by an incoming connection (or a signal)
       we have to recalculate the time until the next queue run should
       occur. select may put a value into tm, but doc for select() says
       we should not use it.*/
    if(qival > 0){
      time(&time_now);
      if(sel_ret == 0){ /* we are either just starting or did a queue run */
	tm.tv_sec = qival;
	tm.tv_usec = 0;
	time_before = time_now;
      }else{
	tm.tv_sec = qival - (time_now - time_before);
	tm.tv_usec = 0;

	/* race condition, very unlikely (but possible): */
	if(tm.tv_sec < 0)
	  tm.tv_sec = 0;
      }
    }
    /* Block until input arrives on one or more active sockets,
       or signal arrives,
       or queuing interval time elapsed (if qival > 0) */
    read_fd_set = active_fd_set;
    if ((sel_ret = select(FD_SETSIZE, &read_fd_set, NULL, NULL,
			  qival > 0 ? &tm : NULL)) < 0){
      if(errno != EINTR){
	logwrite(LOG_ALERT, "select: (terminating): %s\n", strerror(errno));
	exit (EXIT_FAILURE);
      }else{
	if(sighup_seen){
	  logwrite(LOG_NOTICE, "HUP signal received. Restarting daemon\n");

	  for(i = 0; i < FD_SETSIZE; i++)
	    if(FD_ISSET(i, &active_fd_set))
	      close(i);

	  execv(argv[0], &(argv[0]));
	  logwrite(LOG_ALERT, "restarting failed: %s\n", strerror(errno));
	  exit(EXIT_FAILURE);
	}
      }
    }
    else if(sel_ret > 0){
      for(i = 0; i < FD_SETSIZE; i++){
	if (FD_ISSET (i, &read_fd_set)){
	  int sock = i;
	  int new;
	  size = sizeof (clientname);
	  new = accept (sock,
			(struct sockaddr *) &clientname,
			&size);
	  if (new < 0){
	    logwrite(LOG_ALERT, "accept: (terminating): %s\n",
		     strerror(errno));
	    exit (EXIT_FAILURE);
	  }
	
	  accept_connect(sock, new, &clientname);
	}
      }
    }else{
      /* If select returns 0, the interval time has elapsed.
	 We start a new queue runner process */
      int pid;
      signal(SIGCHLD, SIG_IGN);
      if((pid = fork()) == 0){
	queue_run();

	exit(EXIT_SUCCESS);
      }
      else if(pid < 0){
	logwrite(LOG_ALERT, "could not fork for queue run");
      }
    }
  }
}
