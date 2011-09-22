/* base64.c, Copyright 2000 (C) Oliver Kurth,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* see also RFC 1341 */

#include <glib.h>
#include <string.h>
#include "base64.h"

gchar*
base64_encode(guchar *buf, gint len)
{
	guchar *outbuf, *q;
	gchar enc[64];
	gint i = 0, j = 0;
	guint in0, in1, in2;

	for (; i < 26; i++)
		enc[i] = (gchar) ('A' + j++);
	j = 0;
	for (; i < 52; i++)
		enc[i] = (gchar) ('a' + j++);
	j = 0;
	for (; i < 62; i++)
		enc[i] = (gchar) ('0' + j++);
	enc[i++] = '+';
	enc[i++] = '/';

	outbuf = g_malloc(((len + 3) * 8) / 6 +1);
	memset(outbuf, 0, ((len + 3) * 8) / 6 +1);
	q = outbuf;

	i = 0;
	while (i < len - 2) {
		in0 = buf[i++];
		in1 = buf[i++];
		in2 = buf[i++];

		*(q++) = enc[(in0 >> 2) & 0x3f];
		*(q++) = enc[((in0 << 4) | (in1 >> 4)) & 0x3f];
		*(q++) = enc[((in1 << 2) | (in2 >> 6)) & 0x3f];
		*(q++) = enc[in2 & 0x3f];
	}
	if ((len - i) == 1) {
		in0 = buf[i++];
		*(q++) = enc[(in0 >> 2) & 0x3f];
		*(q++) = enc[(in0 << 4) & 0x3f];
		*(q++) = '=';
		*(q++) = '=';
	} else if ((len - i) == 2) {
		in0 = buf[i++];
		in1 = buf[i++];
		*(q++) = enc[(in0 >> 2) & 0x3f];
		*(q++) = enc[((in0 << 4) | (in1 >> 4)) & 0x3f];
		*(q++) = enc[(in1 << 2) & 0x3f];
		*(q++) = '=';
	}
	*q = 0;

	return outbuf;
}

gchar *base64_decode(gchar *buf, gint *size)
{
	guchar *p = buf, *q;
	guint in[4];
	/* gchar *out = g_malloc(((strlen(buf)+3) * 3) / 4 + 1); */
	gchar *out = g_malloc((strlen(buf) + 3) + 1 +1);
	memset(out, 0, (strlen(buf) + 3) + 1 +1);

	q = out;
	*size = 0;

	*q = 0;

	while (*p) {
		int i = 0;
		while (i < 4) {
			if (!*p)
				break;
			if ((*p >= 'A') && (*p <= 'Z'))
				in[i++] = *p - 'A';
			else if ((*p >= 'a') && (*p <= 'z'))
				in[i++] = (*p - 'a') + 26;
			else if ((*p >= '0') && (*p <= '9'))
				in[i++] = (*p - '0') + 52;
			else if (*p == '+')
				in[i++] = 62;
			else if (*p == '/')
				in[i++] = 63;
			else if (*p == '=') {
				in[i++] = 0;
				p++;
				break;
			} else if ((*p != '\r') && (*p != '\n')) {
				p++;
				break;
			}
			p++;
		}
		if ((i == 4) || (p[-1] == '=')) {
			*(q++) = ((in[0] << 2) | (in[1] >> 4));
			*(q++) = ((in[1] << 4) | (in[2] >> 2));
			*(q++) = ((in[2] << 6) | in[3]);
			if (p[-1] == '=') {
				if (i == 3) {
					(*size)++;
				} else if (i == 4) {
					(*size) += 2;
				}
			} else {
				*size += 3;
			}
		}
	}
	out[*size] = '\0';
	return out;
}
