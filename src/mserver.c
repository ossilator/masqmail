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

static
int read_sockline(FILE *in, gchar *buf, int buf_len, int timeout)
{
  gint p = 0, len;
  gint c;

  /*alarm(timeout);*/

  while(isspace(c = getc(in))); ungetc(c, in);

  while((c = getc(in)) != '\n' && (c != EOF)){
    DEBUG(6) debugf("c = %x\n", c);
    if(p >= buf_len-1) { alarm(0); return 0; }
    buf[p++] = c;
  }
  /*alarm(0);*/
  if(c == EOF){
    return 0;
  }
  buf[p] = '\n';
  len = p+1;
  buf[len] = 0;

  DEBUG(4) debugf("<<< %s", buf);

  return len;
}

static
gboolean init_sockaddr (struct sockaddr_in *name,
			const gchar *hostname,
			gushort port)
{
  struct hostent *hostinfo;
  
  name->sin_family = AF_INET;
  name->sin_port = htons (port);
  hostinfo = gethostbyname (hostname);
  if (hostinfo == NULL) {
      DEBUG(3) debugf("Unknown host %s.\r\n", hostname);
      return FALSE;
    }
  name->sin_addr = *(struct in_addr *) hostinfo->h_addr;

  return TRUE;
}

gchar *mserver_detect_online()
{
  struct sockaddr_in saddr;
  gchar *ret = NULL;

  if(init_sockaddr(&saddr, conf.mserver_iface->address,
		   conf.mserver_iface->port)){
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    int dup_sock;
    if(connect(sock, &saddr, sizeof(saddr)) == 0){
      FILE *in, *out;
      char buf[256];

      dup_sock = dup(sock);
      out = fdopen(sock, "w");
      in = fdopen(dup_sock, "r");

      if(read_sockline(in, buf, 256, 15)){
	if(strncmp(buf, "READY", 5) == 0){
	  fprintf(out, "STAT\n"); fflush(out);
	  DEBUG(5) debugf(">>> STAT\n");
	  if(read_sockline(in, buf, 256, 15)){
	    if(strncmp(buf, "DOWN", 4) == 0){
	      DEBUG(1) debugf("no connection.\n");
	      ret = NULL;
	    }else if(strncmp(buf, "UP", 2) == 0){
	      gchar *p = buf+3;
	      while((*p != ':') && *p) p++;
	      if(*p){
		*p = 0;
		p++;
		if((atoi(p) > 0) && *p)
		  ret = g_strdup(buf+3);
		else
		  DEBUG(1) debugf("mserver connection to %s pending\n", buf+3);
	      }else
		logwrite(LOG_ALERT,
			 "unexpected response from mserver after STAT cmd: %s",
			 buf);
	    }else{
	      logwrite(LOG_ALERT,
		       "unexpected response from mserver after STAT cmd: %s",
		       buf);
	    }
	  }
	}
	fprintf(out, "QUIT"); fflush(out);

	close(sock);
	close(dup_sock);
	fclose(in);
	fclose(out);
      }
    }
  }
  return ret;
}
