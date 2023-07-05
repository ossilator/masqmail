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
#include <sys/stat.h>

gchar *connection_name;

void set_online_name(gchar *name)
{
  connection_name = g_strdup(name);
}

gchar *detect_online()
{
  if(conf.online_detect != NULL){
    if(strcmp(conf.online_detect, "file") == 0){
      DEBUG(3) debugf("online detection method 'file'\n");
      if(conf.online_file != NULL){
	struct stat st;
	if(stat(conf.online_file, &st) == 0){
	  FILE *fptr = fopen(conf.online_file, "r");
	  if(fptr){
	    char buf[256];
	    fgets(buf, 256, fptr);
	    g_strchomp(buf);
	    fclose(fptr);
	    return g_strdup(buf);
	  }else{
	    logwrite(LOG_ALERT, "opening of %s failed: %s\n",
		     conf.online_file, strerror(errno));
	    return NULL;
	  }
	}
	else if(errno == ENOENT){
	  logwrite(LOG_NOTICE, "not online.\n");
	  return NULL;
	}else{
	  logwrite(LOG_ALERT, "stat of %s failed: %s",
		   conf.online_file, strerror(errno));
	  return NULL;
	}
      }else
	logwrite(LOG_ALERT,
		 "online detection mode is 'file', "
		 "but online_file is undefined\n");
    }else if(strcmp(conf.online_detect, "mserver") == 0){
      DEBUG(3) debugf("connection method 'mserver'\n");
      return mserver_detect_online();
    }else if(strcmp(conf.online_detect, "argument") == 0){
      return connection_name;
    }else{
      DEBUG(3) debugf("no connection method selected\n");
    }
  }
  return NULL;
}
