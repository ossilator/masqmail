// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include <sys/stat.h>
#include <glob.h>

#include "masqmail.h"

static void
mix_arr(int *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		buf[i] = i;
	for (i = 0; i < len - 1; i++) {
		int j = (int) ((float) (len - i) * ((float) rand()) / (RAND_MAX + 1.0));
		int tmp;

		if (i != j) {
			tmp = buf[i];
			buf[i] = buf[j];
			buf[j] = tmp;
		}
	}
}

GList*
read_queue(void)
{
	GList *msg_list = NULL;
	glob_t gl;
	gchar *pattern;
	int i, *idx_arr;

	/*
	**  Escaping the question marks prevents them from being
	**  interpreted as trigraphs
	*/
	pattern = g_strdup_printf("%s/?????\?-??\?-?\?-H", conf.spool_dir);
	gl.gl_offs = 0;
	glob(pattern, 0, NULL, &gl);

	g_free(pattern);

	DEBUG(4) {
		int i;
		for (i = 0; i < gl.gl_pathc; i++) {
			debugf("spoolfile: %s\n", gl.gl_pathv[i]);
		}
	}

	idx_arr = g_malloc(sizeof(int) * gl.gl_pathc);
	mix_arr(idx_arr, gl.gl_pathc);

	for (i = 0; i < gl.gl_pathc; i++) {
		gchar *uid;

		/* copy 13 chars, offset spooldir path + 1 char for / */
		/* uid length = 6 chars + '-' + 3 chars + '-' + 2 = 13 chars */
		uid = g_strndup(&(gl.gl_pathv[idx_arr[i]][strlen(conf.spool_dir) + 1]), 13);

		DEBUG(5) debugf("uid: %s\n", uid);

		msg_list = g_list_append(msg_list, msg_spool_read(uid));

		DEBUG(5) debugf("after read spool file for %s\n", uid);

		g_free(uid);
	}
	return msg_list;
}

gboolean
queue_run()
{
	GList *msg_list;
	gboolean ok = TRUE;

	logwrite(LOG_NOTICE, "Starting queue run.\n");
	msg_list = read_queue();
	if (msg_list) {
		ok = deliver_msg_list(msg_list, DLVR_ALL);
		DEBUG(5) debugf("  deliver_msg_list() returned: %d\n", ok);
		destroy_msg_list(msg_list);
	}
	logwrite(LOG_NOTICE, "Finished queue run.\n");

	return ok;
}

gboolean
queue_run_online()
{
	GList *msg_list;
	gboolean ok = TRUE;

	logwrite(LOG_NOTICE, "Starting online queue run.\n");
	msg_list = read_queue();
	if (msg_list) {
		ok = deliver_msg_list(msg_list, DLVR_ONLINE);
		DEBUG(5) debugf("  deliver_msg_list() returned: %d\n", ok);
		destroy_msg_list(msg_list);
	}
	logwrite(LOG_NOTICE, "Finished online queue run.\n");

	return ok;
}

static gchar*
format_difftime(double secs)
{
	if (secs > 86400)
		return g_strdup_printf("%.1fd", secs / 86400);
	else if (secs > 3600)
		return g_strdup_printf("%.1fh", secs / 3600);
	else if (secs > 60)
		return g_strdup_printf("%.1fm", secs / 60);
	else
		return g_strdup_printf("%.0fs", secs);
}

void
queue_list()
{
	GList *msg_list;
	GList *msg_node;

	msg_list = read_queue();

	if (msg_list == NULL) {
		printf("mail queue is empty.\n");
		return;
	}

	foreach(msg_list, msg_node) {
		message *msg = (message *) (msg_node->data);
		GList *rcpt_node;
		gchar *size_str = NULL;
		gchar *time_str = NULL;
		gchar *host_str = NULL;
		gchar *ident_str = NULL;

		if (msg->data_size >= 0)
			size_str = g_strdup_printf(" size=%d", msg->data_size);
		if (msg->received_time > 0) {
			gchar *tmp_str;
			time_str = g_strdup_printf(" age=%s", tmp_str = format_difftime(difftime(time(NULL), msg->received_time)));
			g_free(tmp_str);
		}
		if (msg->received_host != NULL)
			host_str = g_strdup_printf(" host=%s", msg->received_host);
		if (msg->ident != NULL)
			ident_str = g_strdup_printf(" ident=%s", msg->ident);

		printf("%s <= %s%s%s%s%s\n", msg->uid, addr_string(msg->return_path), size_str ? size_str : "",
		       time_str ? time_str : "", host_str ? host_str : "", ident_str ? ident_str : "");

		if (size_str)
			g_free(size_str);
		if (time_str)
			g_free(time_str);
		if (host_str)
			g_free(host_str);
		if (ident_str)
			g_free(ident_str);

		foreach(msg->rcpt_list, rcpt_node) {
			address *rcpt = (address *) (rcpt_node->data);

			printf("              %s %s\n", addr_is_delivered(rcpt) ? "=>" : (addr_is_failed(rcpt) ? "!=" : "=="), addr_string(rcpt));
		}
		g_free(msg);
	}
}

gboolean
queue_delete(gchar *uid)
{
	gboolean hdr_ok = TRUE;
	gboolean dat_ok = TRUE;
	gchar *hdr_name = g_strdup_printf("%s/%s-H", conf.spool_dir, uid);
	gchar *dat_name = g_strdup_printf("%s/%s-D", conf.spool_dir, uid);
	struct stat stat_buf;

	if (!spool_lock(uid)) {
		fprintf(stderr, "message %s is locked.\n", uid);
		return FALSE;
	}

	if (stat(hdr_name, &stat_buf) == 0) {
		if (unlink(hdr_name) != 0) {
			fprintf(stderr, "could not unlink %s: %s\n", hdr_name, strerror(errno));
			hdr_ok = FALSE;
		}
	} else {
		fprintf(stderr, "could not stat file %s: %s\n", hdr_name, strerror(errno));
		hdr_ok = FALSE;
	}
	if (stat(dat_name, &stat_buf) == 0) {
		if (unlink(dat_name) != 0) {
			fprintf(stderr, "could not unlink %s: %s\n", dat_name, strerror(errno));
			dat_ok = FALSE;
		}
	} else {
		fprintf(stderr, "could not stat file %s: %s\n", dat_name, strerror(errno));
		dat_ok = FALSE;
	}
	printf("message %s deleted\n", uid);

	spool_unlock(uid);

	return (dat_ok && hdr_ok);
}
