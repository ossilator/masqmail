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

#include <glob.h>

static
void mix_arr(int *buf, int len)
{
  int i;

  for(i = 0; i < len; i++)
    buf[i] = i;
  for(i = 0; i < len-1; i++){
    int j = (int)((float)(len-i) * ((float)rand())/(RAND_MAX + 1.0));
    int tmp;

    if(i != j){
      tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp;
    }
  }
}

GList *read_queue(gboolean do_readdata)
{
  GList *msg_list = NULL;
  glob_t gl;
  gchar **paths;
  gchar *pattern;
  int i, *idx_arr;

  pattern = g_strdup_printf("%s/input/??????-???-??-H", conf.spool_dir);
  gl.gl_offs = 0;
  glob(pattern, 0, NULL, &gl);

  g_free(pattern);

  DEBUG(4){
    int i;
    for(i = 0; i < gl.gl_pathc; i++){
      debugf("spoolfile: %s\n", gl.gl_pathv[i]);
    }
  }

  idx_arr = g_malloc(sizeof(int) * gl.gl_pathc);
  mix_arr(idx_arr, gl.gl_pathc);

  for(i = 0; i < gl.gl_pathc; i++){
    gchar *uid;

    /* copy 13 chars, offset spooldir path + 7 chars for /input/ */
    /* uid length = 6 chars + '-' + 3 chars + '-' + 2 = 13 chars */
    uid = g_strndup(&(gl.gl_pathv[idx_arr[i]][strlen(conf.spool_dir) + 7]), 13);

    DEBUG(5) debugf("uid: %s\n", uid);

    msg_list = g_list_append(msg_list, msg_spool_read(uid, do_readdata));

    DEBUG(5) debugf("after read spool file for %s\n", uid);

    g_free(uid);
  }
  return msg_list;
}

void queue_run()
{
  GList *msg_list;
  gboolean at_least_one = FALSE;
#ifdef WITH_ALIASES
  GList *alias_table = NULL;
  if(conf.alias_file)
    alias_table = table_read(conf.alias_file, ':');
#endif

  logwrite(LOG_NOTICE, "Starting queue run.\n");

  msg_list = read_queue(FALSE);


  if(msg_list != NULL){
    GList *msgout_list = create_msg_out_list(msg_list);
    GList *msgout_node;

    foreach(msgout_list, msgout_node){
      msg_out *msgout = (msg_out *)(msgout_node->data);
#ifndef WITH_ALIASES
      msgout->rcpt_list = g_list_copy(msgout->msg->rcpt_list);
#else
      msgout->rcpt_list = alias_expand(alias_table, msgout->msg->rcpt_list, msgout->msg->non_rcpt_list);
#endif
    }

    /* local deliveries */
    {
      GList *msgout_node;
      GList *rcpt_list;

      foreach(msgout_list, msgout_node){
	msg_out *msgout = (msg_out *)(msgout_node->data);
	GList *rcpt_list;

	rcpt_list = msg_rcptlist_local(msgout->rcpt_list);
	if(rcpt_list != NULL){
	  if(deliver_local(msgout, rcpt_list))
	    at_least_one = TRUE;
	  g_list_free(rcpt_list);
	}
      }
    }

    /* routed local net deliveries: */
    {
      GList *route_node;
      foreach(conf.local_net_routes, route_node){
	connect_route *route = (connect_route *)(route_node->data);
	conf.curr_route = route;
	if(deliver_route_msg_list(route, msgout_list))
	  at_least_one = TRUE;
	conf.curr_route = NULL;
      }
    }
    if(at_least_one)
      deliver_finish_list(msgout_list);
    destroy_msg_out_list(msgout_list);
  }
  destroy_msg_list(msg_list);

#ifdef WITH_ALIASES
  destroy_table(alias_table);
#endif
  logwrite(LOG_NOTICE, "Finished queue run.\n");
}

gboolean run_route_queue(connect_route *route)
{
  GList *msg_list = read_queue(FALSE);
#ifdef WITH_ALIASES
  GList *alias_table = NULL;
  if(conf.alias_file)
    alias_table = table_read(conf.alias_file, ':');
#endif
  if(msg_list){
    GList *msgout_list = create_msg_out_list(msg_list);
    GList *msgout_node;
    foreach(msgout_list, msgout_node){
      msg_out *msgout = (msg_out *)(msgout_node->data);
#ifndef WITH_ALIASES
      msgout->rcpt_list = g_list_copy(msgout->msg->rcpt_list);
#else
      msgout->rcpt_list = alias_expand(alias_table, msgout->msg->rcpt_list, msgout->msg->non_rcpt_list);
#endif
    }
    if(deliver_route_msg_list(route, msgout_list))
      deliver_finish_list(msgout_list);
    destroy_msg_out_list(msgout_list);
    destroy_msg_list(msg_list);

    return TRUE;
  }
  return FALSE;
}

static
gchar *format_difftime(double secs)
{
  if(secs > 86400)
    return g_strdup_printf("%.1fd", secs/86400);
  else if(secs > 3600)
    return g_strdup_printf("%.1fh", secs/3600);
  else if(secs > 60)
    return g_strdup_printf("%.1fm", secs/60);
  else
    return g_strdup_printf("%.0fs", secs);
}  

void queue_list()
{
  GList *msg_list;
  GList *msg_node;

  msg_list = read_queue(FALSE);

  if(msg_list != NULL){
    foreach(msg_list, msg_node){
      message *msg = (message *)(msg_node->data);
      GList *rcpt_node;
      gchar *size_str = NULL;
      gchar *time_str = NULL;
      gchar *host_str = NULL;
    
      if(msg->data_size >= 0)
	size_str = g_strdup_printf("size=%d", msg->data_size);
      if(msg->received_time > 0){
	gchar *tmp_str;
	time_str =
	  g_strdup_printf("age=%s",
			  tmp_str = format_difftime(difftime(time(NULL),
							     msg->received_time)));
	g_free(tmp_str);
      }
      if(msg->received_host != NULL)
	host_str = g_strdup_printf("host=%s", msg->received_host);

      printf("%s <= <%s@%s> %s %s %s\n", msg->uid,
	     msg->return_path->local_part, msg->return_path->domain,
	     size_str ? size_str : "",
	     time_str ? time_str : "",
	     host_str ? host_str : ""
	     );

      if(size_str) g_free(size_str);
      if(time_str) g_free(time_str);
      if(host_str) g_free(host_str);

      foreach(msg->rcpt_list, rcpt_node){
	address *rcpt = (address *)(rcpt_node->data);
      
	printf("              %s <%s@%s>\n",
	       adr_is_delivered(rcpt) ? "=>" : "==",
	       rcpt->local_part, rcpt->domain);
      }
      g_free(msg);
    }
  }else
    printf("mail queue is empty\n");
}
  
