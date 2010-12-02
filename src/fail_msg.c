/*  MasqMail
    Copyright (C) 2000-2001 Oliver Kurth
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

#include <sys/wait.h>

#include "masqmail.h"
#include "peopen.h"
#include "readsock.h"

gboolean
fail_msg(message * msg, gchar * template, GList * failed_rcpts, gchar * err_fmt, va_list args)
{
	gboolean ok = FALSE;
	address *ret_path = NULL;

	/* do not bounce bounces, send to postmaster instead */
	if (msg->return_path->local_part[0] == '\0') {
		GList *node;

		ret_path = create_address_qualified("postmaster", TRUE, conf.host_name);
		foreach(failed_rcpts, node) {
			address *addr = (address *) (node->data);

			if (addr_isequal_parent(addr, ret_path, strcasecmp)) {
				logwrite(LOG_ALERT, "%s == %s: postmaster address failed\n", msg->uid, addr_string(ret_path));
				return FALSE;
			}
		}
	} else
		ret_path = copy_address(msg->return_path);

	DEBUG(1) debugf("sending failure notice to %s.\n", addr_string(ret_path));

	if (template) {
		FILE *file;
		GList *var_table = var_table_conf(var_table_msg(NULL, msg));
		gchar *err_msg = g_strdup_vprintf(err_fmt, args);

		var_table = g_list_prepend(var_table, create_pair_string("err_msg", err_msg));
		g_free(err_msg);

		if ((file = fopen(template, "r"))) {
			FILE *out;
			gchar *cmd;
			pid_t pid;

			cmd = g_strdup_printf(SBINDIR "/masqmail -oi -f <> %s@%s", ret_path->local_part, ret_path->domain);
			if ((out = peidopen(cmd, "w", environ, &pid, conf.mail_uid, conf.mail_gid))) {
				gchar fmt[256], line[256];
				int status, ret;

				while ((ret = read_sockline(file, fmt, 256, 0, 0)) > 0) {
					if (fmt[0] == '@') {
						GList *node;
						if (strncmp(fmt, "@failed_rcpts", 13) == 0) {
							foreach(failed_rcpts, node) {
								address *rcpt = (address *) (node->data);
								fprintf(out, "\t%s\n", addr_string(rcpt));
							}
						} else if (strncmp(fmt, "@msg_headers", 12) == 0) {
							foreach(msg->hdr_list, node) {
								header *hdr = (header *) (node->data);
								fputs(hdr->header, out);
							}
						} else if (strncmp(fmt, "@msg_body", 9) == 0) {
							/* we may have to read the data at this point and remember if we did */
							gboolean flag = (msg->data_list == NULL);
							if (flag) {
								if (!spool_read_data(msg)) {
									logwrite(LOG_ALERT, "could not open data spool file %s\n", msg->uid);
								}
							}
							foreach(msg->data_list, node) {
								gchar *line = (gchar *) (node->data);
								fputs(line, out);
							}
							if (flag)
								msg_free_data(msg);
						}
					} else {
						expand(var_table, fmt, line, 256);
						fputs(line, out);
					}
				}

				fclose(out);
				waitpid(pid, &status, 0);
				if ((WEXITSTATUS(status) != 0) || WIFSIGNALED(status)) {
					if (WEXITSTATUS(status) != 0)
						logwrite(LOG_WARNING, "child returned %d\n", WEXITSTATUS(status));
					if (WIFSIGNALED(status))
						logwrite(LOG_WARNING, "child got signal: %d\n", WTERMSIG(status));
				} else
					ok = TRUE;
			} else {
				logwrite(LOG_ERR, "peopen failed: %s\n", strerror(errno));
			}
			g_free(cmd);
			fclose(file);
		} else
			logwrite(LOG_ALERT, "could not open failure message template %s: %s\n", conf.errmsg_file, strerror(errno));

		destroy_table(var_table);
	}

	destroy_address(ret_path);

	return ok;
}

/*
ival  : |--|--|----|--------|--------|
warned: |-------W-------------W------
result: |nnnyyyynnnnyyyyyyyyyynnnnnnn
*/

static gboolean
warn_msg_is_due(message * msg)
{
	time_t now = time(NULL);

	GList *node;
	for (node = g_list_last(conf.warn_intervals); node; node = g_list_previous(node)) {
		gchar *str_ival = (gchar *) (node->data);
		gint ival = time_interval(str_ival);
		if (ival >= 0) {
			DEBUG(5) debugf("ival = %d\n", ival);
			DEBUG(5) debugf("now - msg->received_time = %d\n", now - msg->received_time);
			if ((now - msg->received_time) > ival) {
				if (msg->warned_time != 0) {
					if ((msg->warned_time - msg->received_time) < ival)
						return TRUE;
				} else
					return TRUE;
			}
		} else
			logwrite(LOG_WARNING, "invalid time interval: %s\n", str_ival);
	}
	return FALSE;
}

gboolean
warn_msg(message * msg, gchar * template, GList * defered_rcpts, gchar * err_fmt, va_list args)
{
	time_t now = time(NULL);

	if (warn_msg_is_due(msg)) {
		if (fail_msg(msg, template, defered_rcpts, err_fmt, args)) {
			msg->warned_time = now;
			return TRUE;
		} else
			return FALSE;
	}
	return TRUE;
}
