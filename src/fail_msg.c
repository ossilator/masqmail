// SPDX-FileCopyrightText: (C) 2000-2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "readsock.h"

#include <sys/wait.h>

gboolean
fail_msg(message *msg, const gchar *template, GList *failed_rcpts, const gchar *err_msg)
{
	gboolean ok = FALSE;
	address *ret_path = NULL;

	/* do not bounce bounces, send to postmaster instead */
	if (msg->return_path->local_part[0] == '\0') {
		ret_path = create_address_raw("postmaster", conf.host_name);
		foreach (recipient *addr, failed_rcpts) {
			if (addr_isequal_parent(addr, ret_path, strcasecmp)) {
				logwrite(LOG_ERR, "%s == <%s>: postmaster address failed\n",
				         msg->uid, ret_path->address);
				return FALSE;
			}
		}
	} else
		ret_path = copy_address(msg->return_path);

	DEBUG(1) debugf("sending failure notice to <%s>.\n", ret_path->address);

	if (template) {
		FILE *file;
		GList *var_table = var_table_conf(var_table_msg(NULL, msg));

		var_table = g_list_prepend(var_table,
				create_pair("err_msg", err_msg));

		if ((file = fopen(template, "r"))) {
			FILE *out;
			pid_t pid;
			int stdin_fd;

			GError *gerr = NULL;
			const gchar * const argv[] = {
				conf.exe_file,
				"-C", conf.conf_file,
				"-oi",
				"-f", "<>",
				ret_path->address,
				NULL
			};
WARNING_PUSH
WARNING_DISABLE("-Wcast-qual")  // glib api bug; g_spawn_async_with_pipes_and_fds() is ok
			gboolean cldok = g_spawn_async_with_pipes(
					NULL /* workdir */, (gchar **) argv, NULL /* env */,
					G_SPAWN_DO_NOT_REAP_CHILD |
							G_SPAWN_CHILD_INHERITS_STDOUT | G_SPAWN_CHILD_INHERITS_STDERR,
					NULL, NULL, /* child setup */
					&pid, &stdin_fd, NULL /* out */, NULL /* err */, &gerr);
WARNING_POP
			if (!cldok) {
				loggerror(LOG_ERR, gerr, "failed to launch child");
			} else {
				gchar fmt[256];

				out = fdopen(stdin_fd, "w");
				while (read_sockline(file, fmt, 256, 0, 0) > 0) {
					if (fmt[0] == '@') {
						if (strncmp(fmt, "@failed_rcpts", 13) == 0) {
							foreach (const recipient *rcpt, failed_rcpts) {
								fprintf(out, "\t<%s>\n", rcpt->address->address);
							}
						} else if (strncmp(fmt, "@msg_headers", 12) == 0) {
							foreach (const header *hdr, msg->hdr_list) {
								fputs(hdr->header, out);
							}
						} else if (strncmp(fmt, "@msg_body", 9) == 0) {
							/* we may have to read the data at this point and remember if we did */
							gboolean flag = (msg->data_list == NULL);
							if (flag) {
								spool_read_data(msg);
							}
							foreach (const gchar *line, msg->data_list) {
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
						logwrite(LOG_ERR, "child returned %d\n", WEXITSTATUS(status));
					}
					if (WIFSIGNALED(status)) {
						logwrite(LOG_ERR, "child got signal: %d\n", WTERMSIG(status));
					}
				} else {
					ok = TRUE;
				}
			}
			fclose(file);
		} else {
			logerrno(LOG_ERR, "could not open failure message template %s",
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
warn_msg_is_due(const message *msg)
{
	time_t now = time(NULL);
	time_t pending = now - msg->received_time;
	time_t warned = msg->warned_time ? msg->warned_time - msg->received_time : -1;
	DEBUG(5) debugf("checking if warning is due for %s; pending = %ld; warned = %ld\n",
	                msg->uid, (long) pending, (long) warned);

	foreach (gconstpointer ival_ptr, conf.warn_intervals) {
		gint ival = (gint) (gintptr) ival_ptr;
		DEBUG(5) debugf("ival = %d\n", ival);
		if (pending > ival) {
			if (warned < ival) {
				return TRUE;
			}
			DEBUG(5) debugf("warned too recently\n");
		}
	}
	return FALSE;
}

gboolean
warn_msg(message *msg, const gchar *template, GList *defered_rcpts, const gchar *err_msg)
{
	time_t now = time(NULL);

	if (warn_msg_is_due(msg)) {
		if (fail_msg(msg, template, defered_rcpts, err_msg)) {
			msg->warned_time = now;
			return TRUE;
		} else {
			return FALSE;
		}
	}
	return TRUE;
}
