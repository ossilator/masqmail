// SPDX-FileCopyrightText: (C) 2000-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#define MAX_VAR 50

GList*
var_table_rcpt(GList *var_table, const address *rcpt)
{
	var_table = g_list_prepend(var_table,
			create_pair("rcpt_local", rcpt->local_part));
	var_table = g_list_prepend(var_table,
			create_pair("rcpt_domain", rcpt->domain));
	var_table = g_list_prepend(var_table,
			create_pair("rcpt", rcpt->address));

	return var_table;
}

GList*
var_table_msg(GList *var_table, const message *msg)
{
	address *ret_path = msg->return_path;

	var_table = g_list_prepend(var_table,
			create_pair("uid", msg->uid));
	var_table = g_list_prepend(var_table,
			create_pair("received_host",
			msg->received_host ? msg->received_host : ""));
	var_table = g_list_prepend(var_table,
			create_pair("ident",
			msg->ident ? msg->ident : ""));
	var_table = g_list_prepend(var_table,
			create_pair("return_path_local",
			ret_path->local_part));
	var_table = g_list_prepend(var_table,
			create_pair("return_path_domain",
			ret_path->domain));
	var_table = g_list_prepend(var_table,
			create_pair("return_path", ret_path->address));

	return var_table;
}

GList*
var_table_conf(GList *var_table)
{
	var_table = g_list_prepend(var_table,
			create_pair("host_name", conf.host_name));
	var_table = g_list_prepend(var_table,
			create_pair("package", PACKAGE_NAME));
	var_table = g_list_prepend(var_table,
			create_pair("version", VERSION));

	return var_table;
}

gint
expand(const GList *var_list, const gchar *format, gchar *result, gint result_len)
{
	const gchar *p = format;
	gchar *q = result;
	gchar *vq;
	gint i = 0;
	gboolean escape = FALSE;

	while (*p && (i < (result_len - 1))) {
		if ((*p == '$') && !escape) {
			const gchar *value;
			gchar var[MAX_VAR + 1];
			int j = 0;

			p++;  /* skip '$' */
			vq = var;

			if (*p == '{') {
				/* ${var} style */
				p++;  /* skip '{' */
				while (*p && (*p != '}') && (j < MAX_VAR)) {
					*(vq++) = *(p++);
					j++;
				}
				p++;
			} else {
				/* $var style */
				while (*p && (isalnum(*p) || (*p=='_') ||
						(*p=='-')) && (j < MAX_VAR)) {
					*(vq++) = *(p++);
					j++;
				}
			}
			*vq = '\0';

			if (j < MAX_VAR) {
				/* search var */
				value = table_find(var_list, var);
				if (value) {
					const gchar *vp = value;
					while (*vp && (i < (result_len - 1))) {
						*(q++) = *(vp++);
						i++;
					}
				}
			}
		} else {
			if ((*p == '\\') && (!escape)) {
				escape = TRUE;
			} else {
				*(q++) = *p;
				i++;
				escape = FALSE;
			}
			p++;
		}
	}
	*q = '\0';

	if (i >= (result_len - 1))
		return -3;

	return i;
}
