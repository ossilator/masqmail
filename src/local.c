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

gboolean append_file(message *msg, GList *hdr_list, gchar *user)
{
  struct passwd *pw;
  gboolean ok = FALSE;
  
  /* headers may be special for a local delivery */
  if(hdr_list == NULL)
    hdr_list = msg->hdr_list;

  if(pw = getpwnam(user)){
    uid_t saved_uid = geteuid();
    gid_t saved_gid = getegid();
    gboolean uid_ok = TRUE, gid_ok = TRUE;

    if(!conf.run_as_user){
      uid_ok = (seteuid(0) == 0);
      if(uid_ok){
	gid_ok = (setegid(conf.mail_gid) == 0);
	uid_ok = (seteuid(pw->pw_uid) == 0);
      }
    }

    DEBUG(5) debugf("running as euid %d\n", geteuid());
    DEBUG(5) debugf("running as egid %d\n", getegid());

    if(uid_ok && gid_ok){
      gchar *filename;
      FILE *out;

      filename = g_strdup_printf("%s/%s", conf.mail_dir, user);
      if(out = fopen(filename, "a")){
	
#ifdef USE_LIBLOCKFILE
        gint err;
        /* lock file using liblockfile */
        err = maillock(user,3);
	if(err == 0) {
#else
	/* lock file: */
	struct flock lock;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_END;
	lock.l_start = lock.l_len = 0;
	if(fcntl(fileno(out), F_SETLK, &lock) != -1){
#endif
	  time_t now = time(NULL);
	  GList *node;

	  fchmod(fileno(out), 0600);

	  fprintf(out, "From <%s@%s> %s", msg->return_path->local_part,
		  msg->return_path->domain, ctime(&now));
	  
	  foreach(hdr_list, node){
	    header *hdr = (header *)(node->data);
	    fputs(hdr->header, out);
	  }
	  putc('\n', out);
	  foreach(msg->data_list, node){
	    /* From hack: */
	    if(strncmp(node->data, "From ", 5) == 0)
	      putc('>', out);
	    fputs(node->data, out);
	  }
	  putc('\n', out);
	  ok = TRUE;
	  
	  /* close when still user */
	  fclose(out);
#ifdef USE_LIBLOCKFILE
          mailunlock();
#endif

	  if(!conf.run_as_user){
	    uid_ok = (seteuid(0) == 0);
	    if(uid_ok){
	      uid_ok = (seteuid(saved_uid) == 0);
	      gid_ok = (setegid(saved_gid) == 0);
	    }
	  }

	  if(!uid_ok || !gid_ok){
	    /* FIXME: if this fails we HAVE to exit, because we shall not run
	       with some users id. But we do not return, and so this message
	       will not be finished, so the user will get the message again
	       next time a delivery is attempted... */
	    logwrite(LOG_ALERT,
		     "could not set back uid or gid after local delivery: %s\n",
		     strerror(errno));
	    exit(EXIT_FAILURE);
	  }
	}else{
	  fclose(out);
#ifdef USE_LIBLOCKFILE
	  DEBUG(3) debugf("could not lock file %s: error %d\n",
			  filename, err);
#else
	  DEBUG(3) debugf("could not lock file %s: %s\n",
			  filename, strerror(errno));
#endif
	}
      }else{
	logwrite(LOG_ALERT, "could not open file %s: %s\n",
		 filename, strerror(errno));
      }
      g_free(filename);
    }else{
      logwrite(LOG_ALERT,
	       "could not set uid or gid for local delivery, uid = %d: %s\n",
	       pw->pw_uid, strerror(errno));
    }
  }else
    logwrite(LOG_ALERT, "could not find password entry for user %s\n", user);

  return ok;
}

gboolean
pipe_out(message *msg, GList *hdr_list, gchar *pname)
{
  gchar *cmd = &(pname[1]);
  FILE *out;
  uid_t saved_uid = geteuid();
  gid_t saved_gid = getegid();
  gboolean ok = FALSE;

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

  out = popen(cmd, "w");
  if(out != NULL){
    GList *node;

    foreach(hdr_list, node){
      header *hdr = (header *)(node->data);
      fputs(hdr->header, out);
    }
    putc('\n', out);
    foreach(msg->data_list, node){
      fputs(node->data, out);
    }
    putc('\n', out);
    if(pclose(out) != 0)
      logwrite(LOG_ALERT, "pclose returned error: %s\n", strerror(errno));
    else
      ok = TRUE;
  }else
    logwrite(LOG_ALERT, "could not open pipe '%s': %s\n", cmd, strerror(errno));

  if(!conf.run_as_user){
    seteuid(saved_uid);
    setegid(saved_gid);
  }
  return ok;
}
    
