/*  MasqMail
    Copyright (C) 1999-2002 Oliver Kurth

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

#include <ctype.h>
#include <glib.h>

#include "masqmail.h"

gint
time_interval(gchar *str)
{
	gchar buf[16];
	gchar *p = str, *q = buf;
	gint factor = 1, val;

	while (*p && isdigit(*p) && (q < buf+sizeof(buf)-1)) {
		*(q++) = *(p++);
	}
	*q = '\0';
	val = atoi(buf);

	/* fall through: */
	switch (*p) {
	case 'w':
		factor *= 7;
	case 'd':
		factor *= 24;
	case 'h':
		factor *= 60;
	case 'm':
		factor *= 60;
	case 's':
		break;
	default:
		return -1;
	}
	return val * factor;
}
