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

header_name header_names[] =
{
  "From", HEAD_FROM,
  "Sender", HEAD_SENDER,
  "To", HEAD_TO,
  "Cc", HEAD_CC,
  "Bcc", HEAD_BCC,
  "Date", HEAD_DATE,
  "Message-Id", HEAD_MESSAGE_ID,
  "Reply-To", HEAD_REPLY_TO,
  "Subject", HEAD_SUBJECT,
  "Return-Path", HEAD_RETURN_PATH,
  "Envelope-To", HEAD_ENVELOPE_TO,
  "Received", HEAD_RECEIVED
};

gchar *prot_names[] =
{
  "local",
  "bsmtp",
  "smtp",
  "esmtp",
  "pop3",
  "(unknown)" /* should not happen, but better than crashing. */
};

gchar *
rec_timestamp()
{
  static gchar buf[64];
  int len;
  
  time_t now = time(NULL);
  struct tm *t = localtime(&now);

  int diff_hour, diff_min;
  struct tm local;
  struct tm *gmt;

  memcpy(&local, t, sizeof(struct tm));
  gmt = gmtime(&now);
  diff_min = 60*(local.tm_hour - gmt->tm_hour) + local.tm_min - gmt->tm_min;
  if (local.tm_year != gmt->tm_year)
    diff_min += (local.tm_year > gmt->tm_year)? 1440 : -1440;
  else if (local.tm_yday != gmt->tm_yday)
    diff_min += (local.tm_yday > gmt->tm_yday)? 1440 : -1440;
  diff_hour = diff_min/60;
  diff_min  = abs(diff_min - diff_hour*60);

  len = strftime(buf, sizeof(buf), "%a, ", &local);
  g_snprintf(buf + len, sizeof(buf) - len, "%02d ", local.tm_mday);
  len += strlen(buf + len);
  len += strftime(buf + len, sizeof(buf) - len, "%b %Y %H:%M:%S", &local);
  g_snprintf(buf + len, sizeof(buf) - len, " %+03d%02d", diff_hour, diff_min);

  return buf;
}

gchar *
string_base62(gchar *res, guint value, gchar len)
{
  static gchar base62_chars[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  gchar *p = res + len;
  *p = 0;
  while (p > res){
    *(--p) = base62_chars[value % 62];
    value /= 62;
  }
  return res;
}

static
int volatile sigtimeout_seen = 0;

static
void sig_timeout_handler(int sig)
{
  sigtimeout_seen = TRUE;
  logwrite(LOG_ERR, "connection timed out (terminating).");
  exit(EXIT_FAILURE);
}

static
void alarm_on(gint timeout)
{
  sigtimeout_seen = FALSE;
  if(timeout > 0)
    alarm(timeout);
}

static
void alarm_off()
{
  alarm(0);
}

static
gint read_line(FILE *in, gchar *buf, gint buf_len,
	       gboolean is_smtp, gboolean dot_terminates)
{
  gint p = 0;
  gint c;

  if(is_smtp)
    alarm_on(5*60);

  while((c = getc(in)) != '\n' && (c != EOF)){
    if(p >= buf_len-1) { alarm_off(); return 0; }
    if((p == 0) && (c == '.') && dot_terminates){
      c = getc(in);
      if((c == '\r') || (c == '\n')){
	if(c == '\r')
	  getc(in);
	if(is_smtp) alarm_off();
	return 0;
      }else
	c = '.';
    }
    buf[p++] = c;
  }

  if(is_smtp)
    alarm_off();

  if(c == EOF){
    /*  if((c == EOF) && dot_terminates){*/
    return -1;
  }

  if(p > 0 && buf[p-1] == '\r')
    p--;
  buf[p++] = '\n';
  buf[p] = 0;

  return p;
}

void header_unfold(header *hdr)
{
  gchar *tmp_hdr = g_malloc(strlen(hdr->header));
  gchar *p = hdr->header, *q = tmp_hdr;
  gboolean flag = FALSE;

  while(*p){
    if(*p != '\n')
      *(q++) = *p;
    else
      flag = TRUE;
    p++;
  }
  *(q++) = '\n';

  if(flag){
    gchar *new_hdr;

    g_free(hdr->header);
    new_hdr = g_strdup(tmp_hdr);
    g_free(tmp_hdr);
    hdr->value = new_hdr + (hdr->value - hdr->header);
    hdr->header = new_hdr;
  }
}

#define MAX_HDR_LEN 72
void header_fold(header *hdr)
{
  gint len = strlen(hdr->header);
  gchar *p, *q;
  /* size is probably overestimated, but so we are on the safe side */
  gchar *tmp_hdr = g_malloc(len + 2*len/MAX_HDR_LEN);

  p = hdr->header;
  q = tmp_hdr;

  if(p[len-1] == '\n')
    p[len-1] = 0;

  while(*p){
    gint i,l;
    gchar *pp;
    
    /* look forward and find potential break points */
    i = 0; l = -1;
    pp = p;
    while(*pp && (i < MAX_HDR_LEN)){
      if((*pp == ' ') || (*pp == '\t'))
	l = i;
      pp++;
      i++;
    }
    if(!*pp) l = pp-p; /* take rest, if EOS found */

    if(l == -1){
      /* no potential break point was found within MAX_HDR_LEN
       so advance further until the next */
      while(*pp && *pp != ' ' && *pp != '\t'){
	pp++;
	i++;
      }
      l = i;
    }

    /* copy */
    i = 0;
    while(i < l){
      *(q++) = *(p++);
      i++;
    }
    *(q++) = '\n';
    *(q++) = *(p++); /* this is either space, tab or 0 */
  }
  {
    gchar *new_hdr;
    
    g_free(hdr->header);
    new_hdr = g_strdup(tmp_hdr);
    g_free(tmp_hdr);
    hdr->value = new_hdr + (hdr->value - hdr->header);
    hdr->header = new_hdr;
  }
}

header *create_header(header_id id, gchar *fmt, ...)
{
  gchar *p;
  header *hdr;
  va_list args;
  va_start(args, fmt);

  if(hdr = g_malloc(sizeof(header))){

    hdr->id = id;
    hdr->header = g_strdup_vprintf(fmt, args);
    hdr->value = NULL;

    p = hdr->header;
    while(*p && *p != ':') p++;
    if(*p)
      hdr->value = p+1;
  }
  return hdr;
}

void destroy_header(header *hdr)
{
  if(hdr){
    if(hdr->header) g_free(hdr->header);
    g_free(hdr);
  }
}

header *copy_header(header *hdr)
{
  header *new_hdr = NULL;

  if(hdr){
    if(new_hdr = g_malloc(sizeof(header))){
      new_hdr->id = hdr->id;
      new_hdr->header = g_strdup(hdr->header);
      new_hdr->value = new_hdr->header + (hdr->value - hdr->header);
    }
  }
  return new_hdr;
}

header *get_header(gchar *line)
{
  gchar *p = line;
  gchar buf[64], *q = buf;
  gint i;
  header *hdr;
  
  while(*p != ':' && q < buf+64) *(q++) = *(p++);
  *q = 0;
  
  if(*p != ':') return NULL;

  hdr = g_malloc(sizeof(header));

  hdr->value = NULL;
  p++;
  if(*p)
    hdr->value = p+1;

  for(i = 0; i < HEAD_NUM_IDS; i++){
    if(strcasecmp(header_names[i].header, buf) == 0)
      break;
  }
  hdr->id = (header_id)i;
  hdr->header = g_strdup(line);
  hdr->value = hdr->header + (hdr->value - line);

  DEBUG(4) debugf("header: %d = %s", hdr->id, hdr->header);

  return hdr;
}

static gint _g_list_addr_isequal(gconstpointer a, gconstpointer b)
{
  return addr_isequal((address *)a, (address *)b);
}

/* accept message from anywhere.
   A locally originating message is indicated by msg->recieved_host == NULL

   If the flags ACC_DEL_RCPTS is set, recipients in the msg->rcpt_list is
   copied and items occuring in it will be removed from the newly constructed
   (from To/Cc/Bcc headers if ACC_RCPT_TO is set) rcpt_list.
*/

accept_error accept_message(FILE *in, message *msg, guint flags)
{
  gchar *line;
  size_t line_size = MAX_DATALINE;
  gboolean in_headers = TRUE;
  header *hdr = NULL;
  prot_id prot = msg->received_prot;
  time_t rec_time = time(NULL);
  struct passwd *passwd = NULL;
  GList *non_rcpt_list;
  gint line_cnt = 0, data_size = 0;

  /* create unique message id */
  msg->uid = g_malloc(14);
  if(msg->uid == NULL){
    logwrite(LOG_ALERT, "out of memory\n");
    exit(EXIT_FAILURE);
  }
  string_base62(msg->uid, rec_time, 6);
  msg->uid[6] = '-';
  string_base62(&(msg->uid[7]), getpid(), 3);
  msg->uid[10] = '-';
  string_base62(&(msg->uid[11]), msg->transfer_id, 2);
  msg->uid[13] = 0;

  line = g_malloc(line_size);
  if(line == NULL){
    logwrite(LOG_ALERT, "out of memory\n");
    exit(EXIT_FAILURE);
  }
  line[0] = 0;

  while(TRUE){
    int len = read_line(in, line, MAX_DATALINE,
			(prot != PROT_LOCAL), (flags & ACC_NODOT_TERM) == 0);

    if(len == 0)
	break;
    else if(len < 0){
      if(flags && ACC_NODOT_TERM)
	break;
      else{
	/* some error occured */
	if(sigtimeout_seen)
	  return AERR_TIMEOUT;
	else
	  return AERR_EOF;
      }
    }
    else{
      if(in_headers){
	if(line[0] == ' ' || line[0] == '\t'){
	  /* continuation of 'folded' header: */
	  if(hdr){
	    hdr->header = g_strconcat(hdr->header, line, NULL);
	  }

	}else if(line[0] == '\n'){
	  /* an empty line marks end of headers */
	  in_headers = FALSE;
	}else{
	  /* in all other cases we expect another header */
	  if(hdr = get_header(line))
	    msg->hdr_list = g_list_append(msg->hdr_list, hdr);
	  else{
	    /* if get_header() returns NULL, no header was recognized,
	       so this seems to be the first data line of a broken mailer
	       which does not send an empty line after the headers */
	    in_headers = FALSE;
	    msg->data_list = g_list_append(msg->data_list, g_strdup(line));
	  }
	}
      }else{
	msg->data_list = g_list_append(msg->data_list, g_strdup(line));
	data_size += strlen(line);
	line_cnt++;
      }
    }
  }
  DEBUG(4) debugf("received %d lines of data (%d bytes)\n",
		  line_cnt, data_size);
  /* we get here after we succesfully
     received the mail data */

  msg->data_size = data_size;
  msg->received_time = time(NULL);

  /* if local, get password entry */
  if(msg->received_host == NULL){
    passwd = g_memdup(getpwuid(geteuid()), sizeof(struct passwd));
  }

  /* set return path if local */
  if(msg->return_path == NULL){

    if(msg->received_host == NULL){
      gchar *path = g_strdup_printf("<%s@%s>",
				    passwd->pw_name, conf.host_name);
      DEBUG(3) debugf("setting return_path for local accept: %s\n", path);
      msg->return_path = create_address(path, TRUE);
      g_free(path);
    }
  }

  /* -t option */
  if(flags & ACC_DEL_RCPTS){
    non_rcpt_list = msg->rcpt_list;
    msg->rcpt_list = NULL;
  }

  /* scan headers */
  {
    gboolean has_id = FALSE;
    gboolean has_date = FALSE;
    gboolean has_sender = FALSE;
    gboolean has_from = FALSE;
    gboolean has_rcpt = FALSE;
    gboolean has_to_or_cc = FALSE;
    GList *hdr_node, *hdr_node_next;
    header *hdr;

    for(hdr_node = g_list_first(msg->hdr_list);
	hdr_node != NULL;
	hdr_node = hdr_node_next){
      hdr_node_next = g_list_next(hdr_node);
      hdr = ((header *)(hdr_node->data));
      DEBUG(5) debugf("scanning headers: %s", hdr->header);
      switch(hdr->id){
      case HEAD_MESSAGE_ID:
	has_id = TRUE; break;
      case HEAD_DATE:
	has_date = TRUE; break;
      case HEAD_FROM:
	has_from = TRUE;
	break;
      case HEAD_SENDER:
	has_sender = TRUE;
	break;
      case HEAD_TO:
      case HEAD_CC:
      case HEAD_BCC:
	has_rcpt = TRUE;
	if(flags & ACC_RCPT_FROM_HEAD){
	  DEBUG(5) debugf("hdr->value = %s\n", hdr->value);
	  if(hdr->value){
	    msg->rcpt_list =
	      adr_list_append_rfc822(msg->rcpt_list, hdr->value);
	  }
	}
	if((flags & ACC_DEL_BCC) && (hdr->id == HEAD_BCC)){
	  DEBUG(3) debugf("removing 'Bcc' header\n");
	  msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
	  g_list_free_1(hdr_node);
	  destroy_header(hdr);
	}else
	  has_to_or_cc = TRUE;
	break;
      case HEAD_ENVELOPE_TO:
	DEBUG(3) debugf("removing 'Envelope-To' header\n");
	msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
	g_list_free_1(hdr_node);
	destroy_header(hdr);
	break;
      case HEAD_RETURN_PATH:
	DEBUG(3) debugf("removing 'Return-Path' header\n");
	msg->hdr_list = g_list_remove_link(msg->hdr_list, hdr_node);
	g_list_free_1(hdr_node);
	destroy_header(hdr);
	break;
      }
    }

    if(flags & ACC_DEL_RCPTS){
      GList *rcpt_node;
      for(rcpt_node = g_list_first(non_rcpt_list);
	  rcpt_node;
	  rcpt_node = g_list_next(rcpt_node)){
	address *rcpt = (address *)(rcpt_node->data);
	GList *node;
	if(node = g_list_find_custom(msg->rcpt_list, rcpt,
				     _g_list_addr_isequal)){
	  msg->rcpt_list = g_list_remove_link(msg->rcpt_list, node);
	  g_list_free_1(node);
	  DEBUG(3) debugf("removing rcpt address %s\n",
			  ((address *)(node->data))->address);
	  destroy_address((address *)(node->data));
	}
      }
    }

    if(!(has_sender || has_from)){
      DEBUG(3) debugf("adding 'From' header\n");
      msg->hdr_list =
	g_list_append(msg->hdr_list,
		      create_header(HEAD_FROM, "From: <%s@%s>\n",
				    msg->return_path->local_part,
				    msg->return_path->domain));
    }
    if((flags & ACC_HEAD_FROM_RCPT) && !has_rcpt){
      GList *node;
      DEBUG(3) debugf("adding 'To' header(s)\n");
      for(node = g_list_first(msg->rcpt_list);
	  node;
	  node = g_list_next(node)){
	address *rcpt = (address *)(node->data);
	msg->hdr_list =
	  g_list_append(msg->hdr_list,
			create_header(HEAD_TO, "To: <%s@%s>\n",
				      rcpt->local_part, rcpt->domain));
      }
    }
    if((flags & ACC_DEL_BCC) && !has_to_or_cc){
      /* Bcc headers have been removed, and there are no remaining rcpt headers */
      DEBUG(3) debugf("adding empty 'Bcc:' header\n");
      msg->hdr_list =
	g_list_append(msg->hdr_list, create_header(HEAD_BCC, "Bcc:\n"));
    }
    if(!has_date){
      DEBUG(3) debugf("adding 'Date:' header\n");
      msg->hdr_list =
	g_list_append(msg->hdr_list,
		      create_header(HEAD_DATE, "Date: %s\n", rec_timestamp()));
    }
    if(!has_id){
      DEBUG(3) debugf("adding 'Message-ID:' header\n");
      msg->hdr_list =
	g_list_append(msg->hdr_list,
		      create_header(HEAD_MESSAGE_ID,
				    "Message-ID: <%s@%s>\n",
				    msg->uid, conf.host_name));
    }
  }

  /* Received header: */
  /* At this point because we have to know the rcpts for the 'for' part */
  if(!(flags & ACC_NO_RECVD_HDR)){
    gchar *for_string = NULL;

    DEBUG(3) debugf("adding 'Received:' header\n");

    if(g_list_length(msg->rcpt_list) == 1){
      address *adr = (address *)(msg->rcpt_list->data);
      for_string = g_strdup_printf(" for %s@%s", adr->local_part, adr->domain);
    }

    if(msg->received_host == NULL){
      hdr = create_header(HEAD_RECEIVED,
			  "Received: from %s by %s"
			  " with %s (%s %s) id %s%s;"
			  " %s\n",
			  passwd->pw_name, conf.host_name,
			  prot_names[prot],
			  PACKAGE, VERSION,
			  msg->uid, for_string ? for_string : "",
			  rec_timestamp());
    }else{
      hdr = create_header(HEAD_RECEIVED,
			  "Received: from %s by %s"
			  " with %s (%s %s) id %s%s;"
			  " %s\n",
			  msg->received_host, conf.host_name,
			  prot_names[prot],
			  PACKAGE, VERSION,
			  msg->uid, for_string ? for_string : "",
			  rec_timestamp());
    }
    header_fold(hdr);
    msg->hdr_list = g_list_prepend(msg->hdr_list, hdr);

    if(for_string) g_free(for_string);
  }

  /* write message to spool: */
  /* accept is no longer responsible for this
  if(!spool_write(msg, TRUE))
    return AERR_NOSPOOL;
  */
  return AERR_OK;
}
