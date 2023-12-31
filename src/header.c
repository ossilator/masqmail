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
#include "masqmail.h"

header_name header_names[] = {
	{"From", HEAD_FROM,},
	{"Sender", HEAD_SENDER,},
	{"To", HEAD_TO,},
	{"Cc", HEAD_CC,},
	{"Bcc", HEAD_BCC,},
	{"Date", HEAD_DATE,},
	{"Message-Id", HEAD_MESSAGE_ID,},
	{"Reply-To", HEAD_REPLY_TO,},
	{"Subject", HEAD_SUBJECT,},
	{"Return-Path", HEAD_RETURN_PATH,},
	{"Envelope-To", HEAD_ENVELOPE_TO,},
	{"Received", HEAD_RECEIVED},
};

/* this was borrowed from exim and slightly changed */
gchar*
rec_timestamp()
{
	static gchar buf[64];
	int len;

	time_t now = time(NULL);
	struct tm *t = localtime(&now);

	int diff_hour, diff_min;
	struct tm local;
	struct tm *gmt;

	memcpy(&local, t, sizeof(struct tm));
	gmt = gmtime(&now);
	diff_min = 60 * (local.tm_hour - gmt->tm_hour) + local.tm_min - gmt->tm_min;
	if (local.tm_year != gmt->tm_year) {
		diff_min += (local.tm_year > gmt->tm_year) ? 1440 : -1440;
	} else if (local.tm_yday != gmt->tm_yday) {
		diff_min += (local.tm_yday > gmt->tm_yday) ? 1440 : -1440;
	}
	diff_hour = diff_min / 60;
	diff_min = abs(diff_min - diff_hour * 60);

	len = strftime(buf, sizeof(buf), "%a, ", &local);
	g_snprintf(buf + len, sizeof(buf) - len, "%02d ", local.tm_mday);
	len += strlen(buf + len);
	len += strftime(buf + len, sizeof(buf) - len, "%b %Y %H:%M:%S", &local);
	g_snprintf(buf + len, sizeof(buf) - len, " %+03d%02d", diff_hour, diff_min);

	return buf;
}

/*
**  finds list of headers matching id
**  if id == HEAD_UNKNOWN and header == NULL finds all unknown headers
**  else finds all headers matching header
*/
GList*
find_header(GList *hdr_list, header_id id, gchar *hdr_str)
{
	GList *found_list = NULL;
	GList *node;

	if ((id != HEAD_UNKNOWN) || !hdr_str) {
		foreach(hdr_list, node) {
			header *hdr = (header *) (node->data);
			if (hdr->id == id) {
				found_list = g_list_append(found_list, hdr);
			}
		}
		return found_list;
	}

	foreach(hdr_list, node) {
		header *hdr = (header *) (node->data);
		gchar buf[64], *q = buf, *p = hdr->header;

		while (*p != ':' && q < buf+sizeof(buf)-1 && *p) {
			*(q++) = *(p++);
		}
		*q = '\0';

		if (strcasecmp(buf, hdr_str) == 0) {
			found_list = g_list_append(found_list, hdr);
		}
	}
	return found_list;
}

void
header_unfold(header *hdr)
{
        char *src = hdr->header;
        char *dest = src;
        char *p;

        p = strchr(src, '\n');
        if (!p || !p[1]) {
                /* no folded header */
                return;
        }

        while (*src) {
                if (*src == '\n') {
                        /* ignore */
                        src++;
                } else {
                        /* copy */
                        *(dest++) = *(src++);
                }
        }
        *(dest++) = '\n';
        *(dest++) = '\0';
}

/*
**  fold the header at maxlen chars (newline excluded)
**  (We exclude the newline because the RFCs deal with it this way)
*/
void
header_fold(header *hdr, unsigned int maxlen)
{
	int len = strlen(hdr->header);
	char *src = hdr->header;
	char *dest;
	char *tmp;
	char *p;
	int valueoffset;

	if (len <= maxlen) {
		/* we don't need to do anything */
		return;
	}

	/* strip trailing whitespace */
	for (p=src+len-1; *p==' '||*p=='\t'||*p=='\n'; p--) {
		*p = '\0';
		len--;
		printf("  trailing whitespace\n");
	}
	printf("stripped len: %d\n", len);

	/*
	**  FIXME: would be nice to have a better size calculation
	**  (the current size + what we insert as break, twice as often as
	**  we have breaks in the optimal case)
	*/
	tmp = malloc(len + 2 * (len/maxlen) * strlen("\n\t"));
	dest = tmp;

	/* the position in hdr->header where the value part start */
	valueoffset = hdr->value - hdr->header;

	while (strlen(src) > maxlen) {
		char *pp;

		for (pp=src+maxlen; pp>src; pp--) {
			if (*pp==' ' || *pp=='\t' || *p=='\n') {
				break;
			}
		}
			
		if (src == pp) {
			/* no potential break point was found within
			   maxlen so advance further until the next */
			for (pp=src+maxlen; *pp; pp++) {
				if (*pp==' ' || *pp=='\t' || *p=='\n') {
					break;
				}
			}
		}
		if (!*pp) {
			break;
		}

		memcpy(dest, src, pp-src);
		dest += pp-src;
		*(dest++) = '\n';
		*(dest++) = '\t';
		while (*pp == ' ' || *pp == '\t' || *p=='\n') {
			pp++;
		}
		src = pp;
	}
	memcpy(dest, src, strlen(src));
	dest += strlen(src);

	if (*(dest-1) != '\n') {
		*dest = '\n';
		*(dest+1) = '\0';
	}

	hdr->header = tmp;
	hdr->value = hdr->header + valueoffset;
}

header*
create_header(header_id id, gchar *fmt, ...)
{
	gchar *p;
	header *hdr;
	va_list args;
	va_start(args, fmt);

	/* g_malloc() calls exit on failure */
	hdr = g_malloc(sizeof(header));

	hdr->id = id;
	hdr->header = g_strdup_vprintf(fmt, args);
	hdr->value = NULL;

	/*
	**  value shall point to the first non-whitespace char in the
	**  value part of the header line (i.e. after the first colon)
	*/
	p = strchr(hdr->header, ':');
	if (p) {
		p++;
		while (*p == ' ' || *p == '\t' || *p == '\n') {
			p++;
		}
		hdr->value = (*p) ? p : NULL;
	}

	DEBUG(3) debugf("create_header():  %s", hdr->header);
	/* DEBUG(3) debugf("create_header(): val: `%s'\n", hdr->value); */

	va_end(args);
	return hdr;
}

void
destroy_header(header *hdr)
{
	if (hdr) {
		if (hdr->header) {
			g_free(hdr->header);
		}
		g_free(hdr);
	}
}

header*
copy_header(header *hdr)
{
	header *new_hdr = NULL;

	if (hdr) {
		new_hdr = g_malloc(sizeof(header));
		new_hdr->id = hdr->id;
		new_hdr->header = g_strdup(hdr->header);
		new_hdr->value = new_hdr->header + (hdr->value - hdr->header);
	}
	return new_hdr;
}

header*
get_header(gchar *line)
{
	gchar *p = line;
	gchar buf[64], *q = buf;
	gint i;
	header *hdr;

	while (*p && (*p != ':') && (q < buf+sizeof(buf)-1)) {
		*(q++) = *(p++);
	}
	*q = '\0';

	if (*p != ':') {
		return NULL;
	}

	hdr = g_malloc(sizeof(header));

	hdr->value = NULL;
	p++;

	while (*p && (*p == ' ' || *p == '\t')) {
		p++;
	}
	hdr->value = p;
	/*
	**  Note: an empty value can also mean that it's only the first part
	**  of a folded header line
	*/

	for (i = 0; i < HEAD_NUM_IDS; i++) {
		if (strcasecmp(header_names[i].header, buf) == 0) {
			break;
		}
	}
	hdr->id = (header_id) i;
	hdr->header = g_strdup(line);
	hdr->value = hdr->header + (hdr->value - line);

	DEBUG(4) debugf("header: %d = %s", hdr->id, hdr->header);
	/* Note: This only outputs the first line if the header is folded */

	return hdr;
}
