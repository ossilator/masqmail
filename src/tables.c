// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2008 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <fnmatch.h>

table_pair*
create_pair_base(gchar *key, gpointer value)
{
	table_pair *pair;

	pair = g_malloc(sizeof(table_pair));
	pair->key = g_strdup(key);
	pair->value = value;

	return pair;
}

table_pair*
create_pair(gchar *key, gchar *value)
{
	return create_pair_base(key, g_strdup(value));
}

table_pair*
parse_table_pair(gchar *line, char delim)
{
	gchar buf[256];
	gchar *p, *q;
	table_pair *pair;

	p = line;
	q = buf;
	while (*p && (*p != delim) && q < buf + 255) {
		*(q++) = *(p++);
	}
	*q = '\0';

	pair = g_malloc(sizeof(table_pair));
	pair->key = g_strdup(g_strstrip(buf));

	if (*p) {
		p++;
		/* while(isspace(*p)) p++; */
		pair->value = g_strdup(g_strstrip(p));
	} else {
		pair->value = g_strdup("");
	}

	return pair;
}

gpointer
table_find_func(GList *table_list, gchar *key,
		int (*cmp_func) (const char *, const char *))
{
	GList *node;

	foreach(table_list, node) {
		table_pair *pair = (table_pair *) (node->data);
		if (cmp_func(pair->key, key) == 0) {
			return pair->value;
		}
	}
	return NULL;
}

gpointer
table_find(GList *table_list, gchar *key)
{
	return table_find_func(table_list, key, strcmp);
}

gpointer
table_find_case(GList *table_list, gchar *key)
{
	return table_find_func(table_list, key, strcasecmp);
}

static int
fnmatch0(const char *pattern, const char *string)
{
	return fnmatch(pattern, string, 0);
}

gpointer
table_find_fnmatch(GList *table_list, gchar *key)
{
	return table_find_func(table_list, key, fnmatch0);
}

GList*
table_read(gchar *fname, gchar delim)
{
	GList *list = NULL;
	FILE *fptr;
	gchar buf[256];

	if (!(fptr = fopen(fname, "rt"))) {
		logerrno(LOG_ERR, "could not open table file %s", fname);
		return NULL;
	}

	while (fgets(buf, sizeof buf, fptr)) {
		if (!*buf || *buf == '#' || *buf == '\n') {
			continue;
		}
		table_pair *pair;
		g_strchomp(buf);
		pair = parse_table_pair(buf, delim);
		list = g_list_append(list, pair);
	}
	fclose(fptr);
	if (!list) {
		logwrite(LOG_NOTICE, "table file %s contained no entries\n",
				fname);
	}
	return list;
}

void
destroy_table(GList *table)
{
	GList *node;

	foreach(table, node) {
		table_pair *p = (table_pair *) (node->data);
		g_free(p->key);
		g_free(p->value);
		g_free(p);
	}
	g_list_free(table);
}
