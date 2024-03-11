// SPDX-FileCopyrightText: (C) 2000-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "peopen.h"
#include "readsock.h"

#include <sys/wait.h>

gboolean
fail_msg(message *msg, gchar *template, GList *failed_rcpts, gchar *err_fmt,
		va_list args)
{
	gboolean ok = FALSE;
	address *ret_path = NULL;

	/* do not bounce bounces, send to postmaster instead */
	if (msg->return_path->local_part[0] == '\0') {
		GList *node;

		ret_path = create_address_qualified("postmaster", TRUE,
				conf.host_name);
		foreach(failed_rcpts, node) {
			address *addr = (address *) (node->data);

			if (addr_isequal_parent(addr, ret_path, strcasecmp)) {
				logwrite(LOG_ALERT, "%s == %s: postmaster "
						"address failed\n", msg->uid,
						addr_string(ret_path));
				return FALSE;
			}
		}
	} else
		ret_path = copy_address(msg->return_path);

	DEBUG(1) debugf("sending failure notice to %s.\n",
			addr_string(ret_path));

	if (template) {
		FILE *file;
		GList *var_table = var_table_conf(var_table_msg(NULL, msg));
		gchar *err_msg = g_strdup_vprintf(err_fmt, args);

		var_table = g_list_prepend(var_table,
				create_pair_string("err_msg", err_msg));
		g_free(err_msg);

		if ((file = fopen(template, "r"))) {
			FILE *out;
			gchar *cmd;
			pid_t pid;

			cmd = g_strdup_printf(SBINDIR "/masqmail -oi -f <> %s@%s", ret_path->local_part, ret_path->domain);
			if (!(out = peopen(cmd, "w", environ, &pid))) {
				logerrno(LOG_ERR, "peopen failed");
			} else {
				gchar fmt[256];

				while (read_sockline(file, fmt, 256, 0, 0) > 0) {
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
								spool_read_data(msg);
							}
							foreach(msg->data_list, node) {
								gchar *line = (gchar *) (node->data);
								fputs(line, out);
							}
							if (flag)
								msg_free_data(msg);
						}
					} else {
						gchar line[256];
						expand(var_table, fmt, line, 256);
						fputs(line, out);
					}
				}

				fclose(out);
				int status;
				waitpid(pid, &status, 0);
				if ((WEXITSTATUS(status) != 0) ||
						WIFSIGNALED(status)) {
					if (WEXITSTATUS(status)) {
						logwrite(LOG_WARNING, "child returned %d\n", WEXITSTATUS(status));
					}
					if (WIFSIGNALED(status)) {
						logwrite(LOG_WARNING, "child got signal: %d\n", WTERMSIG(status));
					}
				} else {
					ok = TRUE;
				}
			}
			g_free(cmd);
			fclose(file);
		} else {
			logerrno(LOG_ALERT, "could not open failure message template %s",
			         conf.errmsg_file);
		}

		destroy_table(var_table);
	}

	destroy_address(ret_path);

	return ok;
}

/*
**  ival  : |--|--|----|--------|--------|
**  warned: |-------W-------------W------
**  result: |nnnyyyynnnnyyyyyyyyyynnnnnnn
*/
static gboolean
warn_msg_is_due(message *msg)
{
	time_t now = time(NULL);
	DEBUG(5) debugf("checking if warning is due for %s; now - msg->received_time = %d\n",
	                msg->uid, now - msg->received_time);

	GList *node;
	for (node = g_list_last(conf.warn_intervals); node;
			node = g_list_previous(node)) {
		gchar *str_ival = (gchar *) (node->data);
		gint ival = time_interval(str_ival);
		if (ival < 0) {
			logwrite(LOG_WARNING, "invalid time interval: %s\n",
					str_ival);
		} else {
			DEBUG(5) debugf("ival = %d\n", ival);
			if ((now - msg->received_time) > ival) {
				if (msg->warned_time == 0) {
					return TRUE;
				}
				if ((msg->warned_time - msg->received_time) <
						ival) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

gboolean
warn_msg(message *msg, gchar *template, GList *defered_rcpts, gchar *err_fmt,
		va_list args)
{
	time_t now = time(NULL);

	if (warn_msg_is_due(msg)) {
		if (fail_msg(msg, template, defered_rcpts, err_fmt, args)) {
			msg->warned_time = now;
			return TRUE;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}
