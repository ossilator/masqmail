// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2008 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <ctype.h>
#include <fnmatch.h>

table_pair*
create_pair_base(const gchar *key, gpointer value)
{
	table_pair *pair;

	pair = g_malloc(sizeof(table_pair));
	pair->key = g_strdup(key);
	pair->value = value;

	return pair;
}

table_pair*
create_pair(const gchar *key, const gchar *value)
{
	return create_pair_base(key, g_strdup(value));
}

table_pair*
parse_table_pair(const gchar *line, char delim)
{
	gchar buf[256];
	table_pair *pair;

	const gchar *p = line;
	gchar *q = buf;
	while (*p && (*p != delim) && q < buf + 255) {
		*(q++) = *(p++);
	}
	*q = '\0';

	pair = g_malloc(sizeof(table_pair));
	pair->key = g_strdup(g_strchomp(buf));

	if (*p) {
		while (isspace(*++p)) {}
		pair->value = g_strdup(p);
	} else {
		pair->value = g_strdup("");
	}

	return pair;
}

gconstpointer
table_find_func(const GList *table_list, const gchar *key,
		int (*cmp_func) (const char *, const char *))
{
	foreach (const table_pair *pair, table_list) {
		if (cmp_func(pair->key, key) == 0) {
			return pair->value;
		}
	}
	return NULL;
}

gconstpointer
table_find(const GList *table_list, const gchar *key)
{
	return table_find_func(table_list, key, strcmp);
}

gconstpointer
table_find_casefold(const GList *table_list, const gchar *key)
{
	return table_find_func(table_list, key, strcasecmp);
}

static int
fnmatch0(const char *pattern, const char *string)
{
	return fnmatch(pattern, string, 0);
}

gconstpointer
table_find_fnmatch(const GList *table_list, const gchar *key)
{
	return table_find_func(table_list, key, fnmatch0);
}

static int
fnmatch_casefold(const char *pattern, const char *string)
{
	return fnmatch(pattern, string, FNM_CASEFOLD);
}

gconstpointer
table_find_fnmatch_casefold(const GList *table_list, const gchar *key)
{
	return table_find_func(table_list, key, fnmatch_casefold);
}

GList*
table_read(const gchar *fname, gchar delim)
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
		logwrite(LOG_NOTICE, "table file %s contained no entries\n", fname);
	}
	return list;
}

void
destroy_pair_base(table_pair *p)
{
	g_free(p->key);
	g_free(p);
}

void
destroy_pair(table_pair *p)
{
	g_free(p->value);
	destroy_pair_base(p);
}

void
destroy_table(GList *table)
{
	g_list_free_full(table, (GDestroyNotify) destroy_pair);
}
