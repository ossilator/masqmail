/*  MasqMail
    Copyright (C) 2000 Oliver Kurth

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
#include "readsock.h"

volatile int _timeout_seen = 0;

static
void sig_timeout_handler(int sig)
{
  _timeout_seen = 1;
}

static
void alarm_on(int timeout)
{
  _timeout_seen = 0;
  signal(SIGALRM, sig_timeout_handler);
  if(timeout > 0)
    alarm(timeout);
}

static
void alarm_off()
{
  alarm(0);
  signal(SIGALRM, SIG_DFL);
}

static
void _read_chug(FILE *in)
{
  int c = 0;

  c = getc(in);
  while(isspace(c) && !_timeout_seen && (c != EOF)) c = getc(in);
  ungetc(c, in);
}

static
int _read_line(FILE *in, char *buf, int buf_len, int timeout)
{
  int p = 0;
  int c = 0;

  c = getc(in);
  while((c != '\n') && (c != EOF) && (p < buf_len-1) && !_timeout_seen){
    buf[p++] = c;
    c = getc(in);
  }

  buf[p] = 0;

  if(c == EOF)
    return -1;
  else if(p >= buf_len){
    ungetc(c, in);
    return -2;
  }
  else if(_timeout_seen)
    return -3;

  buf[p++] = c; /* \n */
  buf[p] = 0;

  return p;
}

int read_sockline(FILE *in, char *buf, int buf_len, int timeout, unsigned int flags)
{
  int p = 0;

  alarm_on(timeout);

  /* strip leading spaces */
  if(flags & READSOCKL_CHUG){
    _read_chug(in);
  }

  p = _read_line(in, buf, buf_len, timeout);

  alarm_off();

  if(p > 1){
    /* here we are sure that buf[p-1] == '\n' */
    if(flags & READSOCKL_CVT_CRLF){
      if((buf[p-2] == '\r') && (buf[p-1] == '\n')){
	buf[p-2] = '\n';
	buf[p-1] = 0;
	p--;
      }
    }
  }
  return p;
}

int read_sockline1(FILE *in, char **pbuf, int *buf_len, int timeout, unsigned int flags)
{
  int p = 0, size = *buf_len;
  char *buf;

  alarm_on(timeout);

  /* strip leading spaces */
  if(flags & READSOCKL_CHUG){
    _read_chug(in);
  }

  if(!*pbuf) *pbuf = g_malloc(size);
  buf = *pbuf;
  
  while(1){
    int pp;

    pp = _read_line(in, buf, size, timeout);
    if(pp == -2){
      *pbuf = g_realloc(*pbuf, *buf_len + size);
      buf = *pbuf + *buf_len;
      *buf_len += size;
      p += size;
    }
    else{
      if(pp > 0) p += pp;
      else p = pp;
      break;
    }
  }

  alarm_off();

  if(p > 1){
    buf = *pbuf;
    /* here we are sure that buf[p-1] == '\n' */
    if(flags & READSOCKL_CVT_CRLF){
      if((buf[p-2] == '\r') && (buf[p-1] == '\n')){
	buf[p-2] = '\n';
	buf[p-1] = 0;
	p--;
      }
    }
  }
  return p;
}

