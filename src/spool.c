// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "dotlock.h"

#include <sys/stat.h>

static gint
read_line(FILE *in, gchar *buf, gint buf_len)
{
	gint p = 0;
	gint c;

	while ((c = getc(in)) != '\n' && (c != EOF)) {
		if (p >= buf_len - 1) {
			buf[buf_len-1] = '\0';
			ungetc(c, in);
			return buf_len;
		}
		buf[p++] = c;
	}

	if (c == EOF) {
		return -1;
	}
	if ((p > 0) && (buf[p - 1] == '\r'))
		p--;
	buf[p++] = '\n';
	buf[p] = '\0';

	return p;
}

static void
spool_write_rcpt(FILE *out, recipient *rcpt)
{
	gchar dlvrd_char = addr_is_delivered(rcpt) ? 'X' : (addr_is_failed(rcpt) ? 'F' : ' ');

	if (rcpt->address->local_part[0] != '|') {
		fprintf(out, "RT:%c<%s>\n", dlvrd_char, rcpt->address->address);
	} else {
		fprintf(out, "RT:%c%s\n", dlvrd_char, rcpt->address->address);
	}
}

static recipient*
spool_scan_rcpt(gchar *line)
{
	recipient *rcpt = NULL;

	if (!line[3]) {
		logwrite(LOG_ERR, "empty recipient in spool\n");
		return NULL;
	}
	if (line[4] == '|') {
		rcpt = create_recipient_pipe(line + 4);
	} else {
		rcpt = create_recipient(line + 4, NULL);
		if (!rcpt) {
			logwrite(LOG_ERR, "failed to parse recipient address '%s' from spool: %s\n",
			         line + 4, parse_error);
			return NULL;
		}
	}
	if (line[3] == 'X') {
		addr_mark_delivered(rcpt);
	} else if (line[3] == 'F') {
		addr_mark_failed(rcpt);
	}
	return rcpt;
}

gboolean
spool_read_data(message *msg)
{
	FILE *in;
	gchar *spool_file;

	DEBUG(5) debugf("spool_read_data entered\n");
	spool_file = g_strdup_printf("%s/%s-D", conf.spool_dir, msg->uid);
	DEBUG(5) debugf("reading data spool file '%s'\n", spool_file);
	in = fopen(spool_file, "r");
	if (!in) {
		logerrno(LOG_ERR, "could not open spool data file %s", spool_file);
		g_free(spool_file);
		return FALSE;
	}
	g_free(spool_file);

	char buf[MAX_DATALINE];

	/* msg uid */
	read_line(in, buf, MAX_DATALINE);

	/* data */
	msg->data_list = NULL;
	while (read_line(in, buf, MAX_DATALINE) > 0) {
		msg->data_list = g_list_prepend(msg->data_list, g_strdup(buf));
	}
	msg->data_list = g_list_reverse(msg->data_list);
	fclose(in);
	return TRUE;
}

static gboolean
spool_read_header(message *msg)
{
	FILE *in;
	gchar *spool_file;

	/* header spool: */
	spool_file = g_strdup_printf("%s/%s-H", conf.spool_dir, msg->uid);
	in = fopen(spool_file, "r");
	if (!in) {
		logerrno(LOG_ERR, "could not open spool header file %s", spool_file);
		g_free(spool_file);
		return FALSE;
	}
	g_free(spool_file);

	header *hdr = NULL;
	char buf[MAX_DATALINE];

	/* msg uid */
	read_line(in, buf, MAX_DATALINE);

	/* envelope header */
	while (read_line(in, buf, MAX_DATALINE) > 0) {
		if (buf[0] == '\n') {
			break;
		} else if (strncasecmp(buf, "MF:", 3) == 0) {
			msg->return_path = create_address(&(buf[3]), A_RFC821, NULL);
			if (!msg->return_path) {
				logwrite(LOG_ERR, "failed to parse return address '%s' from spool: %s\n",
				         &(buf[3]), parse_error);
				fclose(in);
				return FALSE;
			}
			DEBUG(3) debugf("spool_read: MAIL FROM: %s\n",
					msg->return_path->address);
		} else if (strncasecmp(buf, "RT:", 3) == 0) {
			recipient *addr = spool_scan_rcpt(buf);
			if (!addr) {
				fclose(in);
				return FALSE;
			}
			if (addr_is_finished(addr)) {
				msg->non_rcpt_list = g_list_append(msg->non_rcpt_list, addr);
			} else {
				msg->rcpt_list = g_list_append(msg->rcpt_list, addr);
			}
		} else if (strncasecmp(buf, "PR:", 3) == 0) {
			prot_id i;
			for (i = 0; i < PROT_NUM; i++) {
				if (strncasecmp(prot_names[i], &(buf[3]), strlen(prot_names[i])) == 0) {
					break;
				}
			}
			msg->received_prot = i;
		} else if (strncasecmp(buf, "RH:", 3) == 0) {
			g_strchomp(buf);
			msg->received_host = g_strdup(&(buf[3]));
		} else if (strncasecmp(buf, "ID:", 3) == 0) {
			g_strchomp(buf);
			msg->ident = g_strdup(&(buf[3]));
		} else if (strncasecmp(buf, "DS:", 3) == 0) {
			msg->data_size = atoi(&(buf[3]));
		} else if (strncasecmp(buf, "TR:", 3) == 0) {
			msg->received_time = (time_t) (atoi(&(buf[3])));
		} else if (strncasecmp(buf, "TW:", 3) == 0) {
			msg->warned_time = (time_t) (atoi(&(buf[3])));
		}
		/* so far ignore other tags */
	}

	/* mail headers */
	while (read_line(in, buf, MAX_DATALINE) > 0) {
		if (strncasecmp(buf, "HD:", 3) == 0) {
			DEBUG(6) debugf("spool_read_header(): hdr start\n");
			hdr = get_header(&(buf[3]));
			if (hdr) {
				msg->hdr_list = g_list_append(msg->hdr_list, hdr);
			}
		} else if ((buf[0] == ' ' || buf[0] == '\t') && hdr) {
			DEBUG(6) debugf("spool_read_header(): hdr continuation\n");
			char *tmp = hdr->header;
			/* header continuation */
			hdr->header = g_strconcat(hdr->header, buf, NULL);
			hdr->value = hdr->header + (hdr->value - tmp);
			free(tmp);  /* because g_strconcat() allocs and copies */
		} else {
			break;
		}
	}
	fclose(in);
	return TRUE;
}

message*
msg_spool_read(gchar *uid)
{
	message *msg;
	gboolean ok = FALSE;

	msg = create_message();
	msg->uid = g_strdup(uid);

	DEBUG(4) debugf("msg_spool_read(%s):\n", uid);
	/* header spool: */
	ok = spool_read_header(msg);
	DEBUG(4) debugf("spool_read_header() returned: %d\n", ok);
	if (!ok) {
		destroy_message(msg);
		return NULL;
	}
	return msg;
}

/*
**  write header. uid and gid should already be set to the
**  mail ids. Better call spool_write(msg, FALSE).
*/
static gboolean
spool_write_header(message *msg)
{
	GList *node;
	gchar *spool_file, *tmp_file;
	FILE *out;
	gboolean ok = TRUE;

	/* header spool: */
	tmp_file = g_strdup_printf("%s/%d-H.tmp", conf.spool_dir, getpid());

	if ((out = fopen(tmp_file, "w"))) {
		fprintf(out, "%s\n", msg->uid);
		fprintf(out, "MF:<%s>\n", msg->return_path->address);

		foreach(msg->rcpt_list, node) {
			recipient *rcpt = node->data;
			spool_write_rcpt(out, rcpt);
		}
		foreach(msg->non_rcpt_list, node) {
			recipient *rcpt = node->data;
			spool_write_rcpt(out, rcpt);
		}
		fprintf(out, "PR:%s\n", prot_names[msg->received_prot]);
		if (msg->received_host != NULL)
			fprintf(out, "RH:%s\n", msg->received_host);

		if (msg->ident != NULL)
			fprintf(out, "ID:%s\n", msg->ident);

		if (msg->data_size >= 0)
			fprintf(out, "DS: %" G_GSSIZE_FORMAT "\n", msg->data_size);

		if (msg->received_time > 0)
			fprintf(out, "TR: %lu\n", (gulong) msg->received_time);

		if (msg->warned_time > 0)
			fprintf(out, "TW: %lu\n", (gulong) msg->warned_time);

		fprintf(out, "\n");

		foreach(msg->hdr_list, node) {
			header *hdr = (header *) (node->data);
			fprintf(out, "HD:%s", hdr->header);
		}
		if (fflush(out) == EOF)
			ok = FALSE;
		else if (fdatasync(fileno(out)) != 0) {
			if (errno != EINVAL)  /* some fs do not support this..  I hope this also means that it is not necessary */
				ok = FALSE;
		}
		fclose(out);
		if (ok) {
			spool_file = g_strdup_printf("%s/%s-H", conf.spool_dir, msg->uid);
			DEBUG(4) debugf("spool_file = %s\n", spool_file);
			ok = (rename(tmp_file, spool_file) != -1);
			g_free(spool_file);
		}
	} else {
		logerrno(LOG_ERR, "could not open temporary header spool file '%s'",
		         tmp_file);
		DEBUG(1) debugf("euid = %u, egid = %u\n", geteuid(), getegid());
		ok = FALSE;
	}

	g_free(tmp_file);

	return ok;
}

gboolean
spool_write(message *msg, gboolean do_write_data)
{
	GList *list;
	gchar *spool_file, *tmp_file;
	FILE *out;
	gboolean ok = TRUE;
	/* user can read/write, group can read, others cannot do anything: */
	mode_t saved_mode = umask(026);

	/* header spool: */
	ok = spool_write_header(msg);

	if (ok && do_write_data) {
		/* data spool: */
		tmp_file = g_strdup_printf("%s/%d-D.tmp", conf.spool_dir, getpid());
		DEBUG(4) debugf("tmp_file = %s\n", tmp_file);

		if ((out = fopen(tmp_file, "w"))) {
			fprintf(out, "%s\n", msg->uid);
			for (list = g_list_first(msg->data_list); list != NULL; list = g_list_next(list)) {
				fprintf(out, "%s", (gchar *) (list->data));
			}

			/* possibly paranoid ;-) */
			if (fflush(out) == EOF) {
				ok = FALSE;
			} else if (fdatasync(fileno(out)) != 0) {
				if (errno != EINVAL) {  /* some fs do not support this..  I hope this also means that it is not necessary */
					ok = FALSE;
				}
			}
			fclose(out);
			if (ok) {
				spool_file = g_strdup_printf("%s/%s-D", conf.spool_dir, msg->uid);
				DEBUG(4) debugf("spool_file = %s\n", spool_file);
				ok = (rename(tmp_file, spool_file) != -1);
				g_free(spool_file);
			}
		} else {
			logerrno(LOG_ERR, "could not open temporary data spool file '%s'",
			         tmp_file);
			ok = FALSE;
		}
		g_free(tmp_file);
	}

	umask(saved_mode);

	return ok;
}

#define MAX_LOCKAGE 300

gboolean
spool_lock(gchar *uid)
{
	gchar *hitch_name;
	gchar *lock_name;
	gboolean ok = FALSE;

	hitch_name = g_strdup_printf("%s/%s-%d.lock", conf.lock_dir, uid, getpid());
	lock_name = g_strdup_printf("%s/%s.lock", conf.lock_dir, uid);

	ok = dot_lock(lock_name, hitch_name);
	if (!ok)
		logwrite(LOG_WARNING, "spool file %s is locked\n", uid);

	g_free(lock_name);
	g_free(hitch_name);

	return ok;
}

void
spool_unlock(gchar *uid)
{
	gchar *lock_name;

	lock_name = g_strdup_printf("%s/%s.lock", conf.lock_dir, uid);
	dot_unlock(lock_name);
	g_free(lock_name);
}

void
spool_delete_all(message *msg)
{
	gchar *spool_file;

	/* header spool: */
	spool_file = g_strdup_printf("%s/%s-H", conf.spool_dir, msg->uid);
	if (unlink(spool_file) != 0) {
		logerrno(LOG_ERR, "could not delete spool file %s", spool_file);
	}
	g_free(spool_file);

	/* data spool: */
	spool_file = g_strdup_printf("%s/%s-D", conf.spool_dir, msg->uid);
	if (unlink(spool_file) != 0) {
		logerrno(LOG_ERR, "could not delete spool file %s", spool_file);
	}
	g_free(spool_file);
}
