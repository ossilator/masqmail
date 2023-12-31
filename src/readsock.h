/*
**  MasqMail
**  Copyright (C) 2000 Oliver Kurth
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define READSOCKL_CHUG 0x01
#define READSOCKL_CVT_CRLF 0x02


int read_sockline(FILE *in, char *buf, int buf_len, int timeout, unsigned int flags);
int read_sockline1(FILE *in, char **pbuf, int *size, int timeout, unsigned int flags);
