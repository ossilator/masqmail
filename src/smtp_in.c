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

/*
  I always forget these rfc numbers:
  RFC 821  (SMTP)
  RFC 1869 (ESMTP)
  RFC 1870 (ESMTP SIZE)
  RFC 2197 (ESMTP PIPELINE)
*/

static
int volatile sigtimeout_seen = 0;

static
void sig_timeout_handler(int sig)
{
  sigtimeout_seen = 1;
  logwrite(LOG_ERR, "connection timed out (terminating).");
  exit(EXIT_FAILURE);
}

smtp_cmd smtp_cmds[] =
{
  SMTP_HELO, "HELO",
  SMTP_EHLO, "EHLO",
  SMTP_MAIL_FROM, "MAIL FROM:",
  SMTP_RCPT_TO, "RCPT TO:",
  SMTP_DATA, "DATA",
  SMTP_QUIT, "QUIT",
  SMTP_RSET, "RSET",
  SMTP_NOOP, "NOOP",
  SMTP_HELP, "HELP"
};

static
gint read_sockline(FILE *in, gchar *buf, gint buf_len, gint timeout)
{
  gint p = 0, len;
  gint c;

  sigtimeout_seen = FALSE;
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
smtp_cmd_id get_id(const gchar *line)
{
  gint i;
  for(i = 0; i < SMTP_NUM_IDS; i++){
    if(strncasecmp(smtp_cmds[i].cmd, line, strlen(smtp_cmds[i].cmd)) == 0)
      return (smtp_cmd_id)i;
  }
  return SMTP_ERROR;
}

/* this is a quick hack: we expect the address to be syntactically correct
   and containing the mailbox only:
*/

static
gboolean get_address(gchar *line, gchar *addr)
{
  gchar *p = line, *q = addr;

  /* skip MAIL FROM: and RCPT TO: */
  while(*p != ':') p++;
  p++;

  /* skip spaces: */
  while(isspace(*p)) p++;

  /* get address: */
  while(!isspace(*p)) *(q++) = *(p++);
  *q = 0;

  return TRUE;
}

static
smtp_connection *create_base(gchar *remote_host)
{
  smtp_connection *base = g_malloc(sizeof(smtp_connection));
  if(base){
    base->remote_host = g_strdup(remote_host);

    base->prot = PROT_SMTP;
    base->next_id = 0;
    base->helo_seen = 0;
    base->from_seen = 0;
    base->rcpt_seen = 0;
    base->msg = NULL;

    return base;
  }
  return NULL;
}

static
void smtp_printf(FILE *out, gchar *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  DEBUG(4){
    debugf(">>>\n");  vdebugf(fmt, args);
  }

  vfprintf(out, fmt, args);  fflush(out);

  va_end(args);
}

void smtp_in(FILE *in, FILE *out, gchar *remote_host)
{
  gchar *buffer;
  smtp_cmd_id cmd_id;
  message *msg = NULL;
  smtp_connection *psc;

  DEBUG(5) debugf("smtp_in entered, remote_host = %s\n", remote_host);

  psc = create_base(remote_host);
  psc->msg = msg;

  buffer = (gchar *)g_malloc(BUF_LEN);
  if(buffer){
    /* send greeting string, containing ESMTP: */
    smtp_printf(out, "220 %s MasqMail %s ESMTP\r\n",
		conf.host_name, VERSION);
    
    while(read_sockline(in, buffer, BUF_LEN, 5*60)){
      cmd_id = get_id(buffer);
      
      switch(cmd_id){
      case SMTP_EHLO:
	psc->prot = PROT_ESMTP;
	/* fall through */
      case SMTP_HELO:
	psc->helo_seen = TRUE;

	if(psc->prot == PROT_ESMTP){
	  smtp_printf(out, "250-%s Nice to meet you with ESMTP\r\n",
		      conf.host_name);
	  /* not yet: fprintf(out, "250-SIZE\r\n"); */
	  smtp_printf(out,
		      "250-PIPELINING\r\n"
		      "250 HELP\r\n");
	}else{
	  smtp_printf(out, "250 %s pretty old mailer, huh?\r\n",
		      conf.host_name);
	}
	break;

      case SMTP_MAIL_FROM:
	if(psc->helo_seen && !psc->from_seen){
	  gchar buf[MAX_ADDRESS];
	  address *adr;

	  msg = create_message();
	  msg->received_host = remote_host ? g_strdup(remote_host) : NULL;
	  msg->received_prot = psc->prot;
	  /* get transfer id and increment for next one */
	  msg->transfer_id = (psc->next_id)++;

	  get_address(buffer, buf);
	  if(adr = remote_host ?
	     create_address(buf, TRUE) :
	     create_address_qualified(buf, TRUE, conf.host_name)){
	    if(adr->domain != NULL){
	      psc->from_seen = TRUE;
	      msg->return_path = adr;
		smtp_printf(out, "250 OK %s is a nice guy.\r\n", adr->address);
	    }else{
	      smtp_printf(out,
			  "501 return path must be qualified.\r\n", buf);
	    }
	  }else{
	    smtp_printf(out, "501 %s: syntax error.\r\n", buf);
	  }
	}else{
	  if(!psc->helo_seen)
	    smtp_printf(out, "503 need HELO or EHLO\r\n");
	  else
	    smtp_printf(out, "503 MAIL FROM: already given.\r\n");
	}
	break;

      case SMTP_RCPT_TO:

	if(psc->helo_seen && psc->from_seen){
	  char buf[MAX_ADDRESS];
	  address *adr;

	  get_address(buffer, buf);
	  if(adr = remote_host ?
	     create_address(buf, TRUE) :
	     create_address_qualified(buf, TRUE, conf.host_name)){
	    if(adr->local_part[0] != '|'){
	      if(adr->domain != NULL){
		psc->rcpt_seen = TRUE;
		msg->rcpt_list = g_list_append(msg->rcpt_list, adr);
		smtp_printf(out, "250 OK %s is our friend.\r\n", adr->address);
	      }else{
		smtp_printf(out,
			    "501 recipient address must be qualified.\r\n", buf);
	      }
	    }else
	      smtp_printf(out, "501 %s: no pipe allowed for SMTP connections\r\n", buf);
	  }else{
	    smtp_printf(out, "501 %s: syntax error in address.\r\n", buf);
	  }
	}else{

	  if(!psc->helo_seen)
	    smtp_printf(out, "503 need HELO or EHLO.\r\n");
	  else
	    smtp_printf(out, "503 need MAIL FROM: before RCPT TO:\r\n");
	}
	break;
	  
      case SMTP_DATA:
	if(psc->helo_seen && psc->rcpt_seen){
	  accept_error err;

	  smtp_printf(out, "354 okay, and do not forget the dot\r\n");

	  if((err = accept_message(in, msg, 0))
	     == AERR_OK){
	    if(spool_write(msg, TRUE)){
	      pid_t pid;
	      smtp_printf(out, "250 OK id=%s\r\n", msg->uid);
	      
	      if(remote_host != NULL)
		logwrite(LOG_NOTICE, "%s <= <%s@%s> host=%s with %s\n",
			 msg->uid, msg->return_path->local_part,
			 msg->return_path->domain, remote_host,
			 prot_names[psc->prot]);
	      else
		logwrite(LOG_NOTICE, "%s <= <%s@%s> with %s\n",
			 msg->uid, msg->return_path->local_part,
			 msg->return_path->domain,
			 prot_names[psc->prot]);
	      
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
	      }else{
		DEBUG(1) debugf("queuing forced by configuration or option.\n");
	      }
	    }else{
	      smtp_printf(out, "451 Could not write spool file\r\n");
	      return;
	    }
	  }else{
	    switch(err){
	    case AERR_TIMEOUT:
	      return;
	    case AERR_EOF:
	      return;
	    default:
	      /* should never happen: */
	      smtp_printf(out, "451 Unknown error\r\n");
	      return;
	    }
	  }
	  psc->rcpt_seen = psc->from_seen = FALSE;
	  destroy_message(msg);
	  msg = NULL;
	}else{
	  if(!psc->helo_seen)
	    smtp_printf(out, "503 need HELO or EHLO.\r\n");
	  else
	    smtp_printf(out, "503 need RCPT TO: before DATA\r\n");
	}
	break;
      case SMTP_QUIT:
	smtp_printf(out, "221 goodbye\r\n");
	if(msg != NULL) destroy_message(msg);
	return;
      case SMTP_RSET:
	psc->from_seen = psc->rcpt_seen = FALSE;
	if(msg != NULL)
	  destroy_message(msg);
	msg = NULL;
	smtp_printf(out, "250 OK\r\n");
	break;
      case SMTP_NOOP:
	smtp_printf(out, "250 OK\r\n");
	break;
      case SMTP_HELP:
	{
	  int i;

	  smtp_printf(out, "214-supported commands:\r\n");
	  for(i = 0; i < SMTP_NUM_IDS-1; i++){
	    smtp_printf(out, "214-%s\r\n", smtp_cmds[i].cmd);
	  }
	  smtp_printf(out, "214 %s\r\n", smtp_cmds[i].cmd);
	}
	break;
      default:
	smtp_printf(out, "501 command not recognized\r\n");
	break;
      }
    }
  }
}
