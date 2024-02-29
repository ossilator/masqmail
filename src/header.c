// SPDX-FileCopyrightText: (C) 2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <assert.h>

/* keep in sync with header_id enum! */
static const char * const header_names[] = {
	"From",
	"Sender",
	"To",
	"Cc",
	"Bcc",
	"Date",
	"Message-Id",
	"Reply-To",
	"Mail-Followup-To",
	"Subject",
	"Return-Path",
	"Envelope-To",
	"Received",
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

header *
find_header(GList *hdr_list, header_id id)
{
	GList *node;

	foreach(hdr_list, node) {
		header *hdr = (header *) (node->data);
		if (hdr->id == id) {
			return hdr;
		}
	}
	return NULL;
}

header*
create_header_raw(header_id id, gchar *txt, int offset)
{
	header *hdr = g_malloc(sizeof(header));
	hdr->id = id;
	hdr->header = txt;
	hdr->value = txt + offset;
	return hdr;
}

header*
create_header(header_id id, gchar *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	gchar *txt = g_strdup_vprintf(fmt, args);
	va_end(args);

	DEBUG(3) debugf("create_header():  %s", txt);

	/*
	**  value shall point to the first non-whitespace char in the
	**  value part of the header line (i.e. after the first colon)
	*/
	gchar *p = strchr(txt, ':');
	assert( p );
	p++;
	while (*p == ' ' || *p == '\t' || *p == '\n') {
		p++;
	}

	return create_header_raw(id, txt, p - txt);
}

void
destroy_header(header *hdr)
{
	if (hdr) {
		g_free(hdr->header);
		g_free(hdr);
	}
}

void
destroy_header_list(GList *hdr_list)
{
	g_list_free_full(hdr_list, (GDestroyNotify) destroy_header);
}

header*
get_header(gchar *line)
{
	gchar *p = strchr(line, ':');
	if (!p) {
		return NULL;
	}

	guint i;
	for (i = 0; i < HEAD_UNKNOWN; i++) {
		if (strncasecmp(header_names[i], line, p - line) == 0) {
			break;
		}
	}

	p++;
	while (*p && (*p == ' ' || *p == '\t')) {
		p++;
	}
	/*
	**  Note: an empty value can also mean that it's only the first part
	**  of a folded header line
	*/

	DEBUG(4) debugf("header: %u = %s", i, line);
	/* Note: This only outputs the first line if the header is folded */

	return create_header_raw((header_id) i, g_strdup(line), p - line);
}
