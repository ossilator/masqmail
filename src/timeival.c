// SPDX-FileCopyrightText: (C) 1999-2002 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

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
