/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth

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

/*
#include "masqmail.h"
#include "readsock.h"
#include "mserver.h"
*/

#include "config.h"

/* ugly hack */
#ifndef ENABLE_MSERVER
#define ENABLE_MSERVER 1
#include "mserver.c"
#else
#include "masqmail.h"
#include "readsock.h"
#include "mserver.h"
#endif /* ENABLE_MSERVER */

void logwrite(int pri, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vfprintf(stdout, fmt, args);

  va_end(args);
}

void debugf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vfprintf(stdout, fmt, args);

  va_end(args);
}

int main(int argc, char *argv[])
{
  if(argc == 3){
    interface iface;
    gchar *name;

    iface.address = g_strdup(argv[1]);
    iface.port = atoi(argv[2]);

    name = mserver_detect_online(&iface);

    printf("%s\n", name);

    exit(EXIT_SUCCESS);
  }else{
    fprintf(stderr, "usage %s <host> <port>\n", argv[0]);
    exit(EXIT_FAILURE);
  }
}

