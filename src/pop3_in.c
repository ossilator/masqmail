/* pop3_in.c, Copyright (C) 2000 by Oliver Kurth,
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

/* see RFC 1725 */

#include "masqmail.h"
#include "pop3_in.h"
#include "readsock.h"

#include "md5/global.h"
#include "md5/md5.h"

#ifdef ENABLE_POP3

static
gchar *MD5String (char *string)
{
  MD5_CTX context;
  unsigned char digest[16];
  unsigned int len = strlen (string);
  char str_digest[33];
  int i;

  MD5Init (&context);
  MD5Update (&context, string, len);
  MD5Final (digest, &context);

  for (i = 0;  i < 16;  i++) 
    sprintf(str_digest+2*i, "%02x", digest[i]);

  return g_strdup(str_digest);
}

static
pop3_base *create_pop3base(gint sock, guint flags)
{
  gint dup_sock;

  pop3_base *popb = (pop3_base *)g_malloc(sizeof(pop3_base));

  popb->list_uid_old = NULL;
  popb->drop_list = NULL;
  popb->error = pop3_ok;
  popb->next_id = 0;

  popb->buffer = (gchar *)g_malloc(POP3_BUF_LEN);

  dup_sock = dup(sock);
  popb->out = fdopen(sock, "w");
  popb->in = fdopen(dup_sock, "r");

  popb->timestamp = NULL;

  popb->flags = flags;

  return popb;
}

static
void pop3_printf(FILE *out, gchar *fmt, ...)
{
  gchar buf[256];
  
  va_list args;
  va_start(args, fmt);

  vsnprintf(buf, 255, fmt, args);

  DEBUG(4){
    debugf(">>>%s", buf);
  }

  fprintf(out, "%s", buf);  fflush(out);

  va_end(args);
}

static
gboolean find_uid(pop3_base *popb, gchar *str)
{
  GList *node;

  foreach(popb->list_uid_old, node){
    gchar *uid = (gchar *)(node->data);
    if(strcmp(uid, str) == 0){
      return TRUE;
    }
  }
  return FALSE;
}

static
gboolean write_uidl(pop3_base *popb, gchar *user)
{
  gboolean ok = FALSE;
  GList *node;
  gchar *filename = g_strdup_printf("%s/popuidl/%s@%s",
				    conf.spool_dir,
				    user, popb->remote_host);
  FILE *fptr = fopen(filename, "wt");

  if(fptr){
    foreach(popb->drop_list, node){
      msg_info *info = (msg_info *)(node->data);
      if(info->is_fetched)
	fprintf(fptr, "%s\n", info->uid);
    }
    fclose(fptr);
    ok = TRUE;
  }
  g_free(filename);
  return ok;
}

static
gboolean read_uidl(pop3_base *popb, gchar *user)
{
  gboolean ok = FALSE;
  gchar buf[256];
  gchar *filename = g_strdup_printf("%s/popuidl/%s@%s",
				    conf.spool_dir,
				    user, popb->remote_host);
  FILE *fptr = fopen(filename, "rt");

  if(fptr){
    popb->list_uid_old = NULL;
    while(fgets(buf, 255, fptr)){
      g_strchomp(buf);
      popb->list_uid_old =
	g_list_append(popb->list_uid_old, g_strdup(buf));
    }
    fclose(fptr);
    ok = TRUE;
  }
  g_free(filename);
  return ok;
}

static
gboolean read_response(pop3_base *popb, int timeout)
{
  gint len;

  len = read_sockline(popb->in, popb->buffer, POP3_BUF_LEN, timeout, READSOCKL_CHUG);

  if(len == -3){
    popb->error = pop3_timeout;
    return FALSE;
  }
  else if(len == -2){
    popb->error = pop3_syntax;
    return FALSE;
  }
  else if(len == -1){
    popb->error = pop3_eof;
    return FALSE;
  }
  
  return TRUE;
}

static
gboolean check_response(pop3_base *popb)
{
  char c = popb->buffer[0];

  if(c == '+'){
    popb->error = pop3_ok;
    return TRUE;
  }else if(c == '-')
    popb->error = pop3_fail;
  else
    popb->error = pop3_syntax;
  return FALSE;
}

static
gboolean strtoi(gchar *p, gchar **pend, gint *val)
{
  gchar buf[12];
  gint i = 0;

  while(*p && isspace(*p)) p++;
  if(*p){
    while((i < 11) && isdigit(*p))
      buf[i++] = *(p++);
    buf[i] = 0;
    *val = atoi(buf);
    *pend = p;
    return TRUE;
  }
  return FALSE;
}

static
gboolean check_response_int_int(pop3_base *popb, gint *arg0, gint *arg1)
{
  if(check_response(popb)){
    gchar *p = &(popb->buffer[3]);
    gchar *pe;

    if(strtoi(p, &pe, arg0)){
      DEBUG(5) debugf("arg0 = %d\n", *arg0);
      p = pe;
      if(strtoi(p, &pe, arg1))
	DEBUG(5) debugf("arg1 = %d\n", *arg1);
	return TRUE;
    }
    popb->error = pop3_syntax;
  }
  return FALSE;
}

static
gboolean get_drop_listing(pop3_base *popb)
{
  gchar buf[64];

  DEBUG(5) debugf("get_drop_listing() entered\n");

  while(1){
    gint len = read_sockline(popb->in, buf, 64, POP3_CMD_TIMEOUT, READSOCKL_CHUG);
    if(len > 0){
      if(buf[0] == '.')
	return TRUE;
      else{
	gint number, msg_size;
	gchar *p = buf, *pe;
	if(strtoi(p, &pe, &number)){
	  p = pe;
	  if(strtoi(p, &pe, &msg_size)){
	    msg_info *info = g_malloc(sizeof(msg_info));
	    info->number = number;
	    info->size = msg_size;

	    DEBUG(5) debugf("get_drop_listing(), number = %d, msg_size = %d\n", number, msg_size);

	    info->uid = NULL;
	    info->is_fetched = FALSE;
	    popb->drop_list = g_list_append(popb->drop_list, info);
	  }else{
	    popb->error = pop3_syntax;
	    break;
	  }
	}else{
	  popb->error = pop3_syntax;
	  break;
	}
      }
    }
  }
  return FALSE;
}

static
gboolean get_uid_listing(pop3_base *popb)
{
  gchar buf[64];

  while(1){
    gint len = read_sockline(popb->in, buf, 64, POP3_CMD_TIMEOUT, READSOCKL_CHUG);
    if(len > 0){
      if(buf[0] == '.')
	return TRUE;
      else{
	gint number;
	gchar *p = buf, *pe;
	if(strtoi(p, &pe, &number)){
	  msg_info *info = NULL;
	  GList *drop_node;

	  p = pe;
	  while(*p && isspace(*p)) p++;

	  foreach(popb->drop_list, drop_node){
	    msg_info *curr_info = (msg_info *)(drop_node->data);
	    if(curr_info->number == number){
	      info = curr_info;
	      break;
	    }
	  }
	  if(info){
	    info->uid = g_strdup(p);
	    g_strchomp(info->uid);
	  }

	}else{
	  popb->error = pop3_syntax;
	  break;
	}
      }
    }
  }
  return FALSE;
}

static
gboolean check_init_response(pop3_base *popb)
{
  if(check_response(popb)){
    gchar buf[256];
    gchar *p = popb->buffer;
    gint i = 0;
    if(*p){
      while(*p && (*p != '<')) p++;
      while(*p && (*p != '>') && (i < 255))
	buf[i++] = *(p++);
      buf[i++] = '>';
      buf[i] = 0;

      popb->timestamp = g_strdup(buf);

      return TRUE;
    }
  }
  return FALSE;
}

void pop3_in_close(pop3_base *popb)
{
  GList *node;

  fclose(popb->in);
  fclose(popb->out);

  close(popb->sock);

  foreach(popb->list_uid_old, node){
    gchar *uid = (gchar *)(node->data);
    g_free(uid);
  }
  g_list_free(popb->list_uid_old);

  foreach(popb->drop_list, node){
    msg_info *info = (msg_info *)(node->data);
    if(info->uid) g_free(info->uid);
    g_free(info);
  }
  g_list_free(popb->drop_list);

  if(popb->buffer) g_free(popb->buffer);
  if(popb->timestamp) g_free(popb->timestamp);
}

pop3_base *pop3_in_open(gchar *host, gint port, GList *resolve_list, guint flags)
{
  pop3_base *popb;
  gint sock;
  mxip_addr *addr;

  DEBUG(5) debugf("pop3_in_open entered, host = %s\n", host);

  if((addr = connect_resolvelist(&sock, host, port, resolve_list))){
    /* create structure to hold status data: */
    popb = create_pop3base(sock, flags);
    popb->remote_host = addr->name;

    DEBUG(5){
      struct sockaddr_in name;
      int len;
      getsockname(sock, &name, &len);
      debugf("socket: name.sin_addr = %s\n", inet_ntoa(name.sin_addr));
    }
    return popb;
  }
  return NULL;
}

pop3_base *pop3_in_open_child(gchar *cmd, guint flags)
{
  pop3_base *popb;
  gint sock;

  DEBUG(5) debugf("pop3_in_open_child entered, cmd = %s\n", cmd);

  sock = child(cmd);

  if(sock > 0){

    popb = create_pop3base(sock, flags);
    popb->remote_host = NULL;

    return popb;
  }
  logwrite(LOG_ALERT, "child failed (sock = %d): %s\n", sock, strerror(errno));

  return NULL;
}

gboolean pop3_in_init(pop3_base *popb)
{
  gboolean ok;

  if((ok = read_response(popb, POP3_INITIAL_TIMEOUT))){
    ok = check_init_response(popb);
  }
  if(!ok)
    /*    pop3_in_log_failure(popb, NULL);*/
    logwrite(LOG_ALERT, "pop3 failed\n");
  return ok;
}

gboolean pop3_in_login(pop3_base *popb, gchar *user, gchar *pass)
{
  if(popb->flags & POP3_FLAG_APOP){

    gchar *string = g_strdup_printf("%s%s", popb->timestamp, pass);
    gchar *digest = MD5String(string);
    pop3_printf(popb->out, "APOP %s %s\r\n", user, digest);
    g_free(string);
    g_free(digest);
    if(read_response(popb, POP3_CMD_TIMEOUT)){
      if(check_response(popb))
	return TRUE;
      else
	popb->error = pop3_login_failure;
    }

  }else{

    pop3_printf(popb->out, "USER %s\r\n", user);
    if(read_response(popb, POP3_CMD_TIMEOUT)){
      if(check_response(popb)){
	pop3_printf(popb->out, "PASS %s\r\n", pass);
	if(read_response(popb, POP3_CMD_TIMEOUT)){
	  if(check_response(popb))
	    return TRUE;
	  else
	    popb->error = pop3_login_failure;
	}
      }else{
	popb->error = pop3_login_failure;
      }
    }
  }
  return FALSE;
}

gboolean pop3_in_stat(pop3_base *popb)
{
  pop3_printf(popb->out, "STAT\r\n");
  if(read_response(popb, POP3_CMD_TIMEOUT)){
    gint msg_cnt, mbox_size;
    if(check_response_int_int(popb, &msg_cnt, &mbox_size)){
      popb->msg_cnt = msg_cnt;
      popb->mbox_size = mbox_size;

      return TRUE;
    }
  }
  return FALSE;
}

gboolean pop3_in_list(pop3_base *popb)
{
  pop3_printf(popb->out, "LIST\r\n");
  if(read_response(popb, POP3_CMD_TIMEOUT)){
    if(get_drop_listing(popb)){
      return TRUE;
    }
  }
  return FALSE;
}

gboolean pop3_in_dele(pop3_base *popb, gint number)
{
  pop3_printf(popb->out, "DELE %d\r\n", number);
  if(read_response(popb, POP3_CMD_TIMEOUT)){
    return TRUE;
  }
  return FALSE;
}

message *pop3_in_retr(pop3_base *popb, gint number, address *rcpt)
{
  accept_error err;

  pop3_printf(popb->out, "RETR %d\r\n", number);
  if(read_response(popb, POP3_CMD_TIMEOUT)){
    message *msg = create_message();
    msg->received_host = popb->remote_host;
    msg->received_prot = (popb->flags & POP3_FLAG_APOP) ? PROT_APOP : PROT_POP3;
    msg->transfer_id = (popb->next_id)++;
    msg->rcpt_list = g_list_append(NULL, copy_address(rcpt));

    if((err = accept_message(popb->in, msg, ACC_MAIL_FROM_HEAD)) == AERR_OK)
      return msg;

    destroy_message(msg);
  }
  return NULL;
}  

gboolean pop3_in_uidl(pop3_base *popb)
{
  pop3_printf(popb->out, "UIDL\r\n");
  if(read_response(popb, POP3_CMD_TIMEOUT)){
    if(get_uid_listing(popb)){
      return TRUE;
    }
  }
  return FALSE;
}

gboolean pop3_in_quit(pop3_base *popb)
{
  pop3_printf(popb->out, "QUIT\r\n");
  
  DEBUG(4) debugf("QUIT\n");

  signal(SIGALRM, SIG_DFL);

  return TRUE;
}

gboolean pop3_get(pop3_base *popb,
		  gchar *user, gchar *pass, address *rcpt, gint max_size)
{
  gboolean ok = FALSE;
  
  DEBUG(5) debugf("rcpt = %s@%s\n", rcpt->local_part, rcpt->domain);

  signal(SIGCHLD, SIG_IGN);

  if(pop3_in_init(popb)){
    if(pop3_in_login(popb, user, pass)){
      if(pop3_in_stat(popb)){
	if(popb->msg_cnt > 0){

	  logwrite(LOG_NOTICE, "%d message(s) for user %s at %s\n", popb->msg_cnt, user, popb->remote_host);

	  if(pop3_in_list(popb)){
	    /*	      if(pop3_in_uidl(popb) || (!(popb->flags & POP3_FLAG_UIDL))){*/
	    gboolean do_get = !(popb->flags & POP3_FLAG_UIDL);
	    if(!do_get) do_get = pop3_in_uidl(popb);
	    if(do_get){
	      GList *drop_node;

	      if(popb->flags & POP3_FLAG_UIDL) read_uidl(popb, user);

	      foreach(popb->drop_list, drop_node){

		msg_info *info = (msg_info *)(drop_node->data);
		/*		  if(!find_uid(popb, info->uid) || (!(popb->flags & POP3_FLAG_UIDL))){*/
		gboolean do_get_this = !(popb->flags & POP3_FLAG_UIDL);
		if(!do_get_this) do_get_this = !find_uid(popb, info->uid);
		if(do_get_this){

		  if((info->size < max_size) || (max_size == 0)){

		    message *msg = pop3_in_retr(popb, info->number, rcpt);

		    if(msg){
		      if(spool_write(msg, TRUE)){
			pid_t pid;
			logwrite(LOG_NOTICE, "%s <= <%s@%s> host=%s with %s\n",
				 msg->uid, msg->return_path->local_part,
				 msg->return_path->domain, popb->remote_host,
				 (popb->flags & POP3_FLAG_APOP) ?
				 prot_names[PROT_APOP] : prot_names[PROT_POP3]
				 );
			info->is_fetched = TRUE;
			if(!conf.do_queue){
			  if((pid = fork()) == 0){
			    deliver(msg);
			    exit(EXIT_SUCCESS);
			  }else if(pid < 0){
			    logwrite(LOG_ALERT, "could not fork for delivery, id = %s",
				     msg->uid);
			  }
			}else{
			  DEBUG(1) debugf("queuing forced by configuration or option.\n");
			}
			if(popb->flags & POP3_FLAG_DELETE)
			  pop3_in_dele(popb, info->number);
		      }/* if(spool_write(msg, TRUE)) */
		    }else{
		      logwrite(LOG_ALERT, "retrieving of message %d failed: %d\n", info->number, popb->error);
		    }
		  }/* if((info->size > max_size) ... */
		  else{
		    logwrite(LOG_NOTICE, "size of message #%d (%d) exceeded max_size (%d)\n",
			     info->number, info->size, max_size);
		  }
		}/* if(do_get_this) ... */
		else{
		  if(popb->flags & POP3_FLAG_UIDL){
		    info->is_fetched = TRUE;
		    logwrite(LOG_NOTICE, "message %d (uid = %s) not fetched\n", info->number, info->uid);
		  }
		}
	      }/* foreach() */
	      if(popb->flags & POP3_FLAG_UIDL) write_uidl(popb, user);
	    }/* if(pop3_in_uidl(popb) ... */
	  }/* if(pop3_in_list(popb)) */
	}/* if(popb->msg_cnt > 0) */
	else{
	  logwrite(LOG_NOTICE, "no messages for user %s at %s\n", user, popb->remote_host);
	}
	ok = TRUE;
      }
      pop3_in_quit(popb);
    }else{
      logwrite(LOG_ALERT, "pop3 login failed for user %s, host = %s\n", user, popb->remote_host);
    }
  }
  if(!ok){
    logwrite(LOG_ALERT, "pop3 failed, error = %d\n", popb->error);
  }
  return ok;
}

/* function just to log into a pop server,
   for pop_before_smtp (or is it smtp_after_pop?)
*/

gboolean pop3_login(gchar *host, gint port, GList *resolve_list,
		    gchar *user, gchar *pass, guint flags)
{
  gboolean ok = FALSE;
  pop3_base *popb;

  signal(SIGCHLD, SIG_IGN);

  if((popb = pop3_in_open(host, port, resolve_list, flags))){
    if(pop3_in_init(popb)){
      if(pop3_in_login(popb, user, pass))
	ok = TRUE;
      else
	logwrite(LOG_ALERT, "pop3 login failed for user %s, host = %s\n", user, host);
    }
    pop3_in_close(popb);
  }
  return ok;
}

#endif
