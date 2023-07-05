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

static FILE *logfile = NULL;
static FILE *debugfile = NULL;

gboolean logopen()
{
  gchar *filename;

  if(conf.use_syslog){
    openlog(PACKAGE, LOG_PID, LOG_MAIL);
  }else{
    filename = g_strdup_printf("%s/masqmail.log", conf.log_dir);
    logfile = fopen(filename, "a");
    if(!logfile){
      fprintf(stderr, "could not open log '%s'\n", filename);
      return FALSE;
    }
    g_free(filename);
  }

  if(conf.debug_level > 0){
    filename = g_strdup_printf("%s/debug.log", conf.log_dir);
    debugfile = fopen(filename, "a");
    if(!debugfile){
      fprintf(stderr, "could not open debug log '%s'\n", filename);
      return FALSE;
    }
    g_free(filename);
  }
  return TRUE;
}

void logclose()
{
  if(conf.use_syslog)
    closelog();
  else
    if(logfile) fclose(logfile);
  if(debugfile) fclose(debugfile);
}

void vlogwrite(int pri, const char *fmt, va_list args)
{
  if(conf.use_syslog)
    vsyslog(pri, fmt, args);
  else{
    if(pri <= conf.log_max_pri){
      time_t now = time(NULL);
      struct tm *t = localtime(&now);
      gchar buf[24];
      strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);
      fprintf(logfile, "%s [%d] ", buf, getpid());

      vfprintf(logfile, fmt, args);
      fflush(logfile);
    }
  }
}  

void vdebugwrite(int pri, const char *fmt, va_list args)
{
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  gchar buf[24];
  strftime(buf, 24, "%Y-%m-%d %H:%M:%S", t);

  if(debugfile){
    fprintf(debugfile, "%s [%d] ", buf, getpid());
  
    vfprintf(debugfile, fmt, args);
    fflush(debugfile);
  }else{
    fprintf(stderr, "no debug file, msg was:\n");
    vfprintf(stderr, fmt, args);
  }
}

void logwrite(int pri, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vlogwrite(pri, fmt, args);
  if(debugfile)
    vdebugwrite(pri, fmt, args);

  va_end(args);
}

void debugf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vdebugwrite(LOG_DEBUG, fmt, args);

  va_end(args);
}

void vdebugf(const char *fmt, va_list args)
{
  vdebugwrite(LOG_DEBUG, fmt, args);
}

void maillog(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vlogwrite(LOG_NOTICE, fmt, args);

  va_end(args);
}
