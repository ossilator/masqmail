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
gint read_line(FILE *in, gchar *buf, gint buf_len)
{
  gint p = 0;
  gint c;

  while((c = getc(in)) != '\n' && (c != EOF)){
    if(p >= buf_len-1) { return 0; }
    buf[p++] = c;
  }

  if(c == EOF){
    return -1;
  }
  if(p > 0 && buf[p-1] == '\r')
    p--;
  buf[p++] = '\n';
  buf[p] = 0;

  return p;
}

gboolean spool_read_data(message *msg)
{
  FILE *in;
  gboolean ok = FALSE;
  gchar *spool_file;

  DEBUG(5) debugf("spool_read_data entered\n");
  spool_file = g_strdup_printf("%s/input/%s-D", conf.spool_dir, msg->uid);
  DEBUG(5) debugf("reading data spool file '%s'\n", spool_file);
  if(in = fopen(spool_file, "r")){
    char buf[MAX_DATALINE];
    int len;
    
    /* msg uid */
    read_line(in, buf, MAX_DATALINE);
      
    /* data */
    while((len = read_line(in, buf, MAX_DATALINE)) > 0){
      msg->data_list = g_list_append(msg->data_list, g_strdup(buf));
    }
    fclose(in);
    ok = TRUE;
  }else
    logwrite(LOG_ALERT, "could not open spool data file %s: %s",
	     spool_file, strerror(errno));
  return ok;
}

gboolean spool_read_header(message *msg)
{
  FILE *in;
  gboolean ok = FALSE;
  gchar *spool_file;

  /* header spool: */
  spool_file = g_strdup_printf("%s/input/%s-H", conf.spool_dir, msg->uid);
  if(in = fopen(spool_file, "r")){
    header *hdr = NULL;
    char buf[MAX_DATALINE];
    int len;

    /* msg uid */
    read_line(in, buf, MAX_DATALINE);
    
    /* envelope header */
    while((len = read_line(in, buf, MAX_DATALINE)) > 0){
      if(buf[0] == '\n')
	break;
      else if(strncasecmp(buf, "MF:", 3) == 0){
	msg->return_path = create_address(&(buf[3]), TRUE);
	DEBUG(3) debugf("spool_read: MAIL FROM: %s",
			msg->return_path->address);
      }else if(strncasecmp(buf, "RT:", 3) == 0){
	address *adr;

	if(buf[4] == '|')
	  adr = create_address_pipe(&(buf[4]));
	else
	  adr = create_address(&(buf[4]), TRUE);

	if(buf[3] != 'X'){
	  msg->rcpt_list = g_list_append(msg->rcpt_list, adr);
	  DEBUG(3) debugf("spool_read: RCPT TO: %s", adr->address);
	}else{
	  adr_mark_delivered(adr);
	  msg->non_rcpt_list = g_list_append(msg->non_rcpt_list, adr);
	  DEBUG(3) debugf("spool_read: RCPT TO (delivered): %s", adr->address);
	}
      }else if(strncasecmp(buf, "PR:", 3) == 0){
	prot_id i;
	for(i = 0; i < PROT_NUM; i++){
	  if(strncasecmp(prot_names[i], &(buf[3]),
			 strlen(prot_names[i])) == 0){
	    break;
	  }
	}
	msg->received_prot = i;
      }else if(strncasecmp(buf, "RH:", 3) == 0){
	g_strchomp(buf);
	msg->received_host = g_strdup(&(buf[3]));
      }else if(strncasecmp(buf, "DS:", 3) == 0){
	msg->data_size = atoi(&(buf[3]));
      }else if(strncasecmp(buf, "TR:", 3) == 0){
	msg->received_time = (time_t)(atoi(&(buf[3])));
      }
      /* so far ignore other tags */
    }
    
    /* mail headers */
    while((len = read_line(in, buf, MAX_DATALINE)) > 0){
      if(strncasecmp(buf, "HD:", 3) == 0){
	hdr = get_header(&(buf[3]));
	msg->hdr_list = g_list_append(msg->hdr_list, hdr);
      }else if((buf[0] == ' ' || buf[0] == '\t') && hdr){
	/* header continuation */
	hdr->header = g_strconcat(hdr->header, buf, NULL);
      }else
	break;
    }
    fclose(in);
    ok = TRUE;
  }else
    logwrite(LOG_ALERT, "could not open spool header file %s: %s",
	     spool_file, strerror(errno));
  return ok;
}

message *msg_spool_read(gchar *uid, gboolean do_readdata)
{
  message *msg;
  FILE *in;
  gboolean ok = FALSE;
  gchar *spool_file;
  
  msg = create_message();
  msg->uid = g_strdup(uid);

  /* header spool: */
  ok = spool_read_header(msg);
  if(ok && do_readdata){
    /* data spool: */
    ok = spool_read_data(msg);
  }
  return msg;
}

/* write header. uid and gid should already be set to the
   mail ids. Better call spool_write(msg, FALSE).
*/
gboolean spool_write_header(message *msg)
{
  GList *node;
  gchar *spool_file, *tmp_file;
  FILE *out;
  gboolean ok = TRUE;

  /* header spool: */
  tmp_file = g_strdup_printf("%s/input/%d-H.tmp", conf.spool_dir, getpid());
  DEBUG(4) debugf("tmp_file = %s\n", tmp_file);

  if(out = fopen(tmp_file, "w")){
    DEBUG(6) debugf("opened tmp_file %s\n", tmp_file);

    fprintf(out, "%s\n", msg->uid);
    fprintf(out, "MF:<%s@%s>\n",
	    msg->return_path->local_part, msg->return_path->domain);

    DEBUG(6) debugf("after MF\n");
    foreach(msg->rcpt_list, node){
      address *rcpt = (address *)(node->data);
#ifndef WITH_ALIASES
      fprintf(out, "RT:%c<%s@%s>\n",
	      adr_is_delivered(rcpt) ? 'X' : ' ',
	      rcpt->local_part, rcpt->domain);
#else
      if(!adr_is_delivered(rcpt))
	fprintf(out, "RT: <%s@%s>\n", rcpt->local_part, rcpt->domain);
#endif	
    }
#ifdef WITH_ALIASES
    foreach(msg->non_rcpt_list, node){
      address *rcpt = (address *)(node->data);
      fprintf(out, "RT:X<%s@%s>\n",
	      rcpt->local_part, rcpt->domain);
    }
#endif    
    DEBUG(6) debugf("after RT\n");
    fprintf(out, "PR:%s\n", prot_names[msg->received_prot]);
    if(msg->received_host != NULL)
      fprintf(out, "RH:%s\n", msg->received_host);

    if(msg->data_size >= 0)
      fprintf(out, "DS: %d\n", msg->data_size);

    if(msg->received_time > 0)
      fprintf(out, "TR: %d\n", msg->received_time);

    DEBUG(6) debugf("after RH\n");
    fprintf(out, "\n");

    foreach(msg->hdr_list, node){
      header *hdr = (header *)(node->data);
      fprintf(out, "HD:%s", hdr->header);
    }
    if(fflush(out) == EOF) ok = FALSE;
    else if(fdatasync(fileno(out)) != 0) ok = FALSE;
    fclose(out);
    if(ok){
      spool_file = g_strdup_printf("%s/input/%s-H", conf.spool_dir, msg->uid);
      DEBUG(4) debugf("spool_file = %s\n", spool_file);
      ok = (rename(tmp_file, spool_file) != -1);
      g_free(spool_file);
    }
  }else{
    logwrite(LOG_ALERT, "could not open temporary header spool file: %s\n", strerror(errno));
    DEBUG(1) debugf("euid = %d, egid = %d\n", geteuid(), getegid());
    ok = FALSE;
  }
  return ok;
}

gboolean spool_write(message *msg, gboolean do_write_data)
{
  GList *list;
  gchar *spool_file, *tmp_file;
  FILE *out;
  gboolean ok = TRUE;
  uid_t saved_uid = geteuid();
  gid_t saved_gid = getegid();
  /* user can read/write, group can read, others cannot do anything: */
  mode_t saved_mode = saved_mode = umask(026);

  /* set uid and gid to the mail ids */
  if(!conf.run_as_user){
    seteuid(0);

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

  /* header spool: */
  ok = spool_write_header(msg);

  if(ok){

    if(do_write_data){
      /* data spool: */
      tmp_file = g_strdup_printf("%s/input/%d-D.tmp",
				 conf.spool_dir, getpid());
      DEBUG(4) debugf("tmp_file = %s\n", tmp_file);

      if(out = fopen(tmp_file, "w")){
	fprintf(out, "%s\n", msg->uid);
	for(list = g_list_first(msg->data_list);
	    list != NULL;
	    list = g_list_next(list)){
	  fprintf(out, "%s", list->data);
	}

	/* possibly paranoid ;-) */
	if(fflush(out) == EOF) ok = FALSE;
	else if(fdatasync(fileno(out)) != 0) ok = FALSE;
	fclose(out);
	if(ok){
	  spool_file = g_strdup_printf("%s/input/%s-D",
				       conf.spool_dir, msg->uid);
	  DEBUG(4) debugf("spool_file = %s\n", spool_file);
	  ok = (rename(tmp_file, spool_file) != -1);
	  g_free(spool_file);
	}
      }else{
	logwrite(LOG_ALERT, "could not open temporary data spool file: %s\n",
		 strerror(errno));
	ok = FALSE;
      }
    }
  }

  if(!conf.run_as_user){
    seteuid(saved_uid);
    setegid(saved_gid);
  }

  umask(saved_mode);

  return ok;
}

gboolean spool_delete_all(message *msg)
{
  gchar *spool_file;

  /* header spool: */
  spool_file = g_strdup_printf("%s/input/%s-H", conf.spool_dir, msg->uid);
  if(unlink(spool_file) != 0)
    logwrite(LOG_ALERT, "could not delete spool file %s: %s\n",
	     spool_file, strerror(errno));
  g_free(spool_file);

  /* data spool: */
  spool_file = g_strdup_printf("%s/input/%s-D", conf.spool_dir, msg->uid);
  if(unlink(spool_file) != 0)
    logwrite(LOG_ALERT, "could not delete spool file %s: %s\n",
	     spool_file, strerror(errno));
  g_free(spool_file);

  return TRUE;
}
