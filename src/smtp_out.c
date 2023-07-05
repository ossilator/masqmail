/* smtp_out.c, Copyright (C) Oliver Kurth,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 send bugs to: okurth@uni-sw.gwdg.de
*/

/*
  I always forget these rfc numbers:
  RFC 821  (SMTP)
  RFC 1869 (ESMTP)
  RFC 1870 (ESMTP SIZE)
  RFC 2197 (ESMTP PIPELINE)
*/

/*
#include <glib.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
*/

#include "masqmail.h"
#include "smtp_out.h"

volatile gint timeout_seen = 0;

static
void sig_timeout_handler(int sig)
{
  timeout_seen = 1;
}

void destroy_smtpbase(smtp_base *psb)
{
  fclose(psb->in);
  fclose(psb->out);

  close(psb->sock);

  if(psb->helo_name) g_free(psb->helo_name);
  if(psb->buffer) g_free(psb->buffer);
}

static
smtp_base *create_smtpbase(gint sock)
{
  gint dup_sock;
  gint i;

  smtp_base *psb = (smtp_base *)g_malloc(sizeof(smtp_base));

  psb->sock = sock;

  psb->use_esmtp = FALSE;
  psb->use_size = FALSE;
  psb->use_pipelining = FALSE;

  psb->buffer = (gchar *)g_malloc(SMTP_BUF_LEN);

  dup_sock = dup(sock);
  psb->out = fdopen(sock, "w");
  psb->in = fdopen(dup_sock, "r");

  psb->error = smtp_ok;

  psb->helo_name = NULL;
  
  if(conf.curr_route != NULL){
    if(conf.curr_route->do_correct_helo){
      struct sockaddr_in sname;
      int len = sizeof(struct sockaddr_in);
      struct hostent *host_entry;

      getsockname(sock, &sname, &len);
      debugf("socket: name.sin_addr = %s\n", inet_ntoa(sname.sin_addr));
      host_entry =
	gethostbyaddr((const char *)&(sname.sin_addr),
		      sizeof(sname.sin_addr), AF_INET);
      if(host_entry){
	psb->helo_name = g_strdup(host_entry->h_name);
      }else{
	/* we failed to look up our own name. Instead of giving our local hostname,
	   we may give our IP number to show the server that we are at least
	   willing to be honest. For the really picky ones.*/
	DEBUG(5) debugf("failed to look up own host name.\n");
	psb->helo_name = g_strdup_printf("[%s]", inet_ntoa(sname.sin_addr));
      }
      DEBUG(5) debugf("helo_name = %s\n", psb->helo_name);
    }
  }
  if(psb->helo_name == NULL){
    psb->helo_name = g_strdup(conf.host_name);
  }
  return psb;
}

static
int read_sockline(FILE *in, gchar *buf, int buf_len, int timeout)
{
  gint p = 0, len;
  gint c;

  timeout_seen = 0;
  alarm(timeout);

  while(isspace(c = getc(in))); ungetc(c, in);

  while((c = getc(in)) != '\n' && (c != EOF)){
    if(p >= buf_len-1) { alarm(0); return 0; }
    buf[p++] = c;
  }
  alarm(0);
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
gboolean read_response(smtp_base *psb, int timeout)
{
  gint buf_pos = 0;
  gchar code[5];
  gint i, len;

  do{
    len = read_sockline(psb->in, &(psb->buffer[buf_pos]),
			SMTP_BUF_LEN - buf_pos, timeout);
    if(timeout_seen){
      psb->error = smtp_timeout;
      return FALSE;
    }
    else if(len == 0){
      psb->error = smtp_eof;
      return FALSE;
    }
    for(i = 0; i < 4; i++)
      code[i] = psb->buffer[buf_pos+i];
    code[i] = 0;
    psb->last_code = atoi(code);

    buf_pos += len;

  }while(code[3] == '-');

  return TRUE;
}

static
gboolean check_response(smtp_base *psb, gboolean after_data)
{
  char c = psb->buffer[0];

  if(((c == '2') && !after_data) || ((c == '3') && after_data)){
    psb->error = smtp_ok;
    DEBUG(6) debugf("response OK:'%s' after_date = %d\n", psb->buffer, (int)after_data);
    return TRUE;
  }else{
    if(c == '4')
      psb->error = smtp_trylater;
    else if(c == '5')
      psb->error = smtp_fail;
    else
      psb->error = smtp_syntax;
    DEBUG(6) debugf("response failure:'%s' after_date = %d\n", psb->buffer, (int)after_data);
    return FALSE;
  }
}

static
gboolean check_init_response(smtp_base *psb)
{
  if(check_response(psb, FALSE)){
    psb->use_esmtp = (strstr(psb->buffer, "ESMTP") != NULL);

    DEBUG(4) debugf(psb->use_esmtp ? "uses esmtp\n" : "no esmtp\n");

    return TRUE;
  }
  return FALSE;
}

static
gboolean check_helo_response(smtp_base *psb)
{
  gchar *ptr = psb->buffer;

  if(!check_response(psb, FALSE))
    return FALSE;

  while(*ptr){
    /* TODO: we do not look if server advertises its
       "fixed maximum message size" (RFC 1870). This is
       not required, but we want a good SMTP client, don't we? */

    if(strncasecmp(&(ptr[4]), "SIZE", 4) == 0)
      psb->use_size = TRUE;

    if(strncasecmp(&(ptr[4]), "PIPELINING", 10) == 0)
      psb->use_pipelining = TRUE;

    while(*ptr != '\n') ptr++;
    ptr++;
  }

  DEBUG(4){
    debugf(psb->use_size ? "uses SIZE\n" : "no size\n");
    debugf(psb->use_pipelining ? "uses PIPELINING\n" : "no pipelining\n");
  }

  return TRUE;
}

static
gboolean smtp_helo(smtp_base *psb, gchar *helo)
{
  while(TRUE){
    if(psb->use_esmtp){
      fprintf(psb->out, "EHLO %s\r\n", helo); fflush(psb->out);

      DEBUG(4) debugf("EHLO %s\r\n", helo);

    }else{
      fprintf(psb->out, "HELO %s\r\n", helo); fflush(psb->out);

      DEBUG(4) debugf("HELO %s\r\n", helo);

    }
    
    if(!read_response(psb, SMTP_CMD_TIMEOUT))
      return FALSE;

    if(check_helo_response(psb))
      return TRUE;
    else{
      if(psb->error == smtp_fail){
	if(psb->use_esmtp){
	  /* our guess that server understands EHLO was wrong,
	     try again with HELO
	  */
	  psb->use_esmtp = FALSE;
	}else{
	  /* what sort of server ist THAT ?!
	     give up...
	  */
	  return FALSE;
	}
      }else
	return FALSE;
    }
  }
}

static
void smtp_cmd_mailfrom(smtp_base *psb, address *return_path, guint size)
{
  if(psb->use_size){
    fprintf(psb->out, "MAIL FROM:<%s@%s> SIZE=%d\r\n",
	    return_path->local_part, return_path->domain,
	    size);
    fflush(psb->out);

    DEBUG(4) debugf("MAIL FROM:<%s@%s> SIZE=%d\r\n",
		    return_path->local_part, return_path->domain,
		    size);

  }else{
    fprintf(psb->out, "MAIL FROM:<%s@%s>\r\n", 
	    return_path->local_part, return_path->domain);
    fflush(psb->out);

    DEBUG(4) debugf("MAIL FROM:<%s@%s>\r\n",
		    return_path->local_part, return_path->domain);
  }
}

static
void smtp_cmd_rcptto(smtp_base *psb, address *rcpt)
{
  fprintf(psb->out, "RCPT TO:<%s@%s>\r\n", rcpt->local_part, rcpt->domain);
  fflush(psb->out);
  DEBUG(4) debugf("RCPT TO:<%s@%s>\n", rcpt->local_part, rcpt->domain);
}

static
void send_data_line(smtp_base *psb, gchar *data)
{
  gchar *ptr;

  /* According to RFC 821 each line should be terminated with CRLF.
     Since a dot on a line itself marks the end of data, each line
     beginning with a dot is prepended with another dot.
  */

  ptr = data;
  if(*ptr == '.')
    putc('.', psb->out);
  while(*ptr){
    int c = (int)(*ptr);
    if(*ptr == '\n'){
      putc('\r', psb->out);
      putc('\n', psb->out);
    }else
      putc(c, psb->out);
    ptr++;
  }
}

static
void send_header(smtp_base *psb, GList *hdr_list)
{
  GList *node;
  gint num_hdrs = 0;

  /* header */
  if(hdr_list){
    foreach(hdr_list, node){
      if(node->data){
	header *hdr = (header *)(node->data);
	if(hdr->header){
	  send_data_line(psb, hdr->header);
	  num_hdrs++;
	}
      }
    }
  }

  /* empty line separating headers from data: */
  putc('\r', psb->out);
  putc('\n', psb->out);

  DEBUG(4) debugf("sent %d headers\n", num_hdrs);
}

static
void send_data(smtp_base *psb, message *msg)
{
  GList *node;
  gint num_lines = 0;

  /* data */
  if(msg->data_list){
    for(node = g_list_first(msg->data_list); node; node = g_list_next(node)){
      if(node->data){
	send_data_line(psb, node->data);
	num_lines++;
      }
    }
  }

  DEBUG(4) debugf("sent %d lines of data\n", num_lines);

  fprintf(psb->out, ".\r\n");
  fflush(psb->out);
}

void smtp_out_log_failure(smtp_base *psb, message *msg)
{
  if(msg == NULL){
    if(psb->error == smtp_timeout)
      logwrite(LOG_NOTICE, "host=%s connection timed out.\n",
	       psb->remote_host);
    else if(psb->error == smtp_eof)
      logwrite(LOG_NOTICE,
	       "host=%s connection terminated prematurely.\n",
	       psb->remote_host);
    else if(psb->error == smtp_syntax)
      logwrite(LOG_NOTICE,
	       "host=%s got unexpected response: %s\n",
	       psb->remote_host, psb->buffer);
    else
      /* error message should still be in the buffer */
      logwrite(LOG_NOTICE, "host=%s failed: %s\n",
	       psb->remote_host, psb->buffer);
  }else{
    if(psb->error == smtp_timeout)
      logwrite(LOG_NOTICE, "%s == host=%s connection timed out.\n",
	       msg->uid, psb->remote_host);
    else if(psb->error == smtp_eof)
      logwrite(LOG_NOTICE,
	       "%s == host=%s connection terminated prematurely.\n",
	       msg->uid, psb->remote_host);
    else if(psb->error == smtp_syntax)
      logwrite(LOG_NOTICE,
	       "%s == host=%s got unexpected response: %s\n",
	       msg->uid, psb->remote_host, psb->buffer);
    else
      /* error message should still be in the buffer */
      logwrite(LOG_NOTICE, "%s == host=%s failed: %s\n",
	       msg->uid, psb->remote_host, psb->buffer);
  }
}

smtp_base *smtp_out_open(gchar *host, gint port, GList *resolve_list)
{
  smtp_base *psb;
  gint sock;
  mxip_addr *addr;

  DEBUG(5) debugf("smtp_out_open entered, host = %s\n", host);

  if(addr = connect_resolvelist(&sock, host, port, resolve_list)){
    /* create structure to hold status data: */
    psb = create_smtpbase(sock);
    psb->remote_host = addr->name;

    DEBUG(5){
      struct sockaddr_in name;
      int len = sizeof(struct sockaddr_in);
      getsockname(sock, &name, &len);
      debugf("socket: name.sin_addr = %s\n", inet_ntoa(name.sin_addr));
    }
    return psb;
  }

  return NULL;
}

gboolean smtp_out_rset(smtp_base *psb)
{
  gboolean ok;
  
  fprintf(psb->out, "RSET\r\n"); fflush(psb->out);
  DEBUG(4) debugf("RSET\n");

  if(ok = read_response(psb, SMTP_CMD_TIMEOUT))
    if(check_response(psb, FALSE))
      return TRUE;

  smtp_out_log_failure(psb, NULL);

  return FALSE;
}

gboolean smtp_out_init(smtp_base *psb)
{
  gboolean ok;

  signal(SIGALRM, sig_timeout_handler);

  if(ok = read_response(psb, SMTP_INITIAL_TIMEOUT)){
    if(ok = check_init_response(psb)){
 
      ok = smtp_helo(psb, psb->helo_name);
    }
  }
  if(!ok)
    smtp_out_log_failure(psb, NULL);
  return ok;
}

gint smtp_out_msg(smtp_base *psb,
		  message *msg, address *return_path, GList *rcpt_list,
		  GList *hdr_list)
{
  gint i, tmp, size;
  /* gshort sock;*/
  gboolean ok;
  void (*old_sighandler)(int);
  int rcpt_cnt;
  int rcpt_accept;

  DEBUG(5) debugf("smtp_out_msg entered\n");

  /* defaults: */
  if(return_path == NULL)
    return_path = msg->return_path;
  if(hdr_list == NULL)
    hdr_list = msg->hdr_list;
  if(rcpt_list == NULL)
    rcpt_list = msg->rcpt_list;
  rcpt_cnt = g_list_length(rcpt_list);

  size = calc_size(msg, TRUE);
  smtp_cmd_mailfrom(psb, return_path,
		    psb->use_size ? 
		    size + SMTP_SIZE_ADD : 0);
      
  if(!psb->use_pipelining){
    if(ok = read_response(psb, SMTP_CMD_TIMEOUT))
      ok = check_response(psb, FALSE);
  }
  if(ok){
    GList *rcpt_node;
    rcpt_accept = 0;

    for(rcpt_node = g_list_first(rcpt_list);
	rcpt_node != NULL;
	rcpt_node = g_list_next(rcpt_node)){
      address *rcpt = (address *)(rcpt_node->data);
      smtp_cmd_rcptto(psb, rcpt);
      if(!psb->use_pipelining){
	if(ok = read_response(psb, SMTP_CMD_TIMEOUT))
	  if(check_response(psb, FALSE)){
	    rcpt_accept++;
	    adr_mark_delivered(rcpt);
	  }
	  else{
	    /* if server returned an error for one recp. we
	       may still try the others. But if it is a timeout, eof
	       or unexpected response, it is more serious and we should
	       give up. */
	    if((psb->error != smtp_trylater) &&
	       (psb->error != smtp_fail)){
	      ok = FALSE;
	      break;
	    }else{
	      logwrite(LOG_NOTICE, "%s == <%s@%s> host=%s failed: %s",
		       msg->uid, rcpt->local_part, rcpt->domain,
		       psb->remote_host, psb->buffer);
	    }
	  }
	else
	  break;
      }
    }

    /* There is no point in going on if no recp.s were accpted.
       But we can check that at this point only if not pipelining: */
    ok = (ok && (psb->use_pipelining || (rcpt_accept > 0)));
    if(ok){

      fprintf(psb->out, "DATA\r\n"); fflush(psb->out);

      DEBUG(4) debugf("DATA\r\n");
	
      if(psb->use_pipelining){
	/* the first pl'ed command was MAIL FROM
	   the last was DATA, whose response can be handled by the 'normal' code
	   all in between were RCPT TO:
	*/
	/* response to MAIL FROM: */
	if(ok = read_response(psb, SMTP_CMD_TIMEOUT)){
	  if(ok = check_response(psb, FALSE)){

	    /* response(s) to RCPT TO:
	       this is very similar to the sequence above for no pipeline
	    */
	    for(i = 0; i < rcpt_cnt; i++){
	      if(ok = read_response(psb, SMTP_CMD_TIMEOUT)){
		address *rcpt = g_list_nth_data(rcpt_list, i);
		if(check_response(psb, FALSE)){
		  rcpt_accept++;
		  adr_mark_delivered(rcpt);
		}
		else{
		  /* if server returned an error 4xx or 5xx for one recp. we
		     may still try the others. But if it is a timeout, eof
		     or unexpected response, it is more serious and we
		     should give up. */
		  if((psb->error != smtp_trylater) &&
		     (psb->error != smtp_fail)){
		    ok = FALSE;
		    break;
		  }else{
		    logwrite(LOG_NOTICE, "%s == <%s@%s> host=%s failed: %s",
			     msg->uid, rcpt->local_part, rcpt->domain,
			     psb->remote_host, psb->buffer);
		  }
		}
	      }else{
		DEBUG(5) debugf("check_response failed after RCPT TO\n");
		break;
	      }
	    }
	    if(rcpt_accept == 0)
	      ok = FALSE;
	  }else{
	    DEBUG(5) debugf("check_response failed after MAIL FROM\n");
	  }
	}else{
	  DEBUG(5) debugf("read_response failed after MAIL FROM\n");
	}
      } /* if(psb->use_pipelining) */

      /* response to the DATA cmd */
      if(ok){
	if(read_response(psb, SMTP_DATA_TIMEOUT)){
	  if(check_response(psb, TRUE)){
	    send_header(psb, hdr_list);
	    send_data(psb, msg);
	      
	    if(read_response(psb, SMTP_FINAL_TIMEOUT))
	      ok = check_response(psb, FALSE);
	  }
	}
      }
    }
  }

  DEBUG(5){
    debugf("psb->error = %d\n", psb->error);
    debugf("ok = %d\n", ok);
    debugf("rcpt_accept = %d\n", rcpt_accept);
  }

  if(psb->error == smtp_ok){
    GList *rcpt_node;
    for(rcpt_node = g_list_first(rcpt_list);
	rcpt_node;
	rcpt_node = g_list_next(rcpt_node)){
      address *rcpt = (address *)(rcpt_node->data);
      if(adr_is_delivered(rcpt))
	logwrite(LOG_NOTICE, "%s => <%s@%s> host=%s with %s\n",
		 msg->uid, rcpt->local_part, rcpt->domain, psb->remote_host,
		 psb->use_esmtp ? "esmtp" : "smtp");
    }
  }else{
    /* if something went wrong,
       we have to unmark the rcpts prematurely marked as delivered */
    GList *rcpt_node;
    for(rcpt_node = g_list_first(rcpt_list);
	rcpt_node;
	rcpt_node = g_list_next(rcpt_node)){
      address *rcpt = (address *)(rcpt_node->data);

      adr_unmark_delivered(rcpt);
    }

    /* log the failure: */
    smtp_out_log_failure(psb, msg);
  }
}

gboolean smtp_out_quit(smtp_base *psb)
{
  fprintf(psb->out, "QUIT\r\n"); fflush(psb->out);
  
  DEBUG(4) debugf("QUIT\n");

  signal(SIGALRM, SIG_DFL);
}
  
gint smtp_deliver(gchar *host, gint port, GList *resolve_list,
		  message *msg,
		  address *return_path,
		  GList *rcpt_list)
{
  smtp_base *psb;
  smtp_error err;
  mxip_addr *addr;

  DEBUG(5) debugf("smtp_deliver entered\n");

  if(psb = smtp_out_open(host, port, resolve_list)){

    /* initiate connection, send message and quit: */
    if(smtp_out_init(psb)){
      smtp_out_msg(psb, msg, return_path, rcpt_list, NULL);
      if(psb->error == smtp_ok ||
	 (psb->error == smtp_fail) ||
	 (psb->error == smtp_trylater) ||
	 (psb->error == smtp_syntax))
	
	smtp_out_quit(psb);
    }
    
    err = psb->error;
    destroy_smtpbase(psb);
    
    return err;
  }
  return -1;
}
