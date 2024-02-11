// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
**
*/

#include "masqmail.h"
#include "peopen.h"

#ifdef USE_LIBLOCKFILE
#  include <maillock.h>
#else
#  include <fcntl.h>
#endif

#include <pwd.h>
#include <sys/wait.h>
#include <sys/stat.h>

static void
message_stream(FILE *out, message *msg, GList *hdr_list, guint flags)
{
	time_t now = time(NULL);
	GList *node;

	if (flags & MSGSTR_FROMLINE) {
		fprintf(out, "From <%s@%s> %s", msg->return_path->local_part,
				msg->return_path->domain, ctime(&now));
	}

	foreach(hdr_list, node) {
		header *hdr = (header *) (node->data);
		fputs(hdr->header, out);
	}
	putc('\n', out);
	foreach(msg->data_list, node) {
		/* From hack: */
		if (flags & MSGSTR_FROMHACK) {
			if (strncmp(node->data, "From ", 5) == 0)
				putc('>', out);
		}
		fputs(node->data, out);
	}
	putc('\n', out);
}

gboolean
append_file(message *msg, GList *hdr_list, gchar *user)
{
	struct passwd *pw;
	gboolean ok = FALSE;
	uid_t saved_uid = geteuid();
	gid_t saved_gid = getegid();
	gboolean uid_ok = TRUE, gid_ok = TRUE;
	gchar *filename;
	FILE *out;

	/* headers may be special for a local delivery */
	if (!hdr_list)
		hdr_list = msg->hdr_list;

	if (!(pw = getpwnam(user))) {
		logwrite(LOG_ALERT, "could not find password entry for "
				"user %s\n", user);
		errno = ENOENT;  /* getpwnam does not set errno correctly */
		return FALSE;
	}

	if (!conf.run_as_user) {
		uid_ok = (seteuid(0) == 0);
		if (uid_ok) {
			gid_ok = (setegid(conf.mail_gid) == 0);
			uid_ok = (seteuid(pw->pw_uid) == 0);
		}
		if (!uid_ok || !gid_ok) {
			logwrite(LOG_ALERT, "could not set uid or gid for "
					"local delivery, uid = %d: %s\n",
					pw->pw_uid, strerror(errno));
			return FALSE;
		}
	}

	DEBUG(5) debugf("running as euid %d, egid %d\n", geteuid(), getegid());

	filename = g_strdup_printf("%s/%s", conf.mail_dir, user);
	if (!(out = fopen(filename, "a"))) {
		logwrite(LOG_ALERT, "could not open file %s: %s\n",
				filename, strerror(errno));
	} else {
#ifdef USE_LIBLOCKFILE
		gint err;
		/* lock file using liblockfile */
		err = maillock(user, 3);
		if (err == 0) {
#else
		/* lock file: */
		struct flock lock;
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_END;
		lock.l_start = lock.l_len = 0;
		if (fcntl(fileno(out), F_SETLK, &lock) != -1) {
#endif
			fchmod(fileno(out), 0600);
			message_stream(out, msg, hdr_list,
					MSGSTR_FROMLINE | MSGSTR_FROMHACK);
			ok = TRUE;

			/* close when still user */
			fclose(out);
#ifdef USE_LIBLOCKFILE
			mailunlock();
#endif
		} else {
			fclose(out);
#ifdef USE_LIBLOCKFILE
			DEBUG(3) debugf("could not lock file %s: error %d\n",
					filename, err);
		}  /* XEmacs indenting convenience... */
#else
			DEBUG(3) debugf("could not lock file %s: %s\n",
					filename, strerror(errno));
		}
#endif
	}
	g_free(filename);

	if (!conf.run_as_user) {
		uid_ok = (seteuid(0) == 0);
		if (uid_ok) {
			gid_ok = (setegid(saved_gid) == 0);
			uid_ok = (seteuid(saved_uid) == 0);
		}
	}

	if (!uid_ok || !gid_ok) {
		/*
		**  FIXME: if this fails we HAVE to exit, because we shall
		**  not run with some users id. But we do not return, and so
		**  this message will not be finished, so the user will get
		**  the message again next time a delivery is attempted...
		*/
		logwrite(LOG_ALERT, "could not set back uid or gid after "
				"local delivery: %s\n", strerror(errno));
		logwrite(LOG_ALERT, "uid=%d, gid=%d, euid=%d, egid=%d, "
				"want = %d, %d\n", getuid(), getgid(),
				geteuid(), getegid(), saved_uid, saved_gid);
		logwrite(LOG_ALERT, "In case of trouble, see "
				"local.c:append_file() for details.\n",
				strerror(errno));
		exit(1);
	}
	return ok;
}

gboolean
pipe_out(message *msg, GList *hdr_list, address *rcpt, gchar *cmd, guint flags)
{
	gchar *envp[40];
	FILE *out;
	uid_t saved_uid = geteuid();
	gid_t saved_gid = getegid();
	gboolean ok = FALSE;
	gint i, n;
	pid_t pid;
	void (*old_signal) (int);
	int status;
	address *ancestor = addr_find_ancestor(rcpt);

	/* set uid and gid to the mail ids */
	if (!conf.run_as_user) {
		set_euidgid(conf.mail_uid, conf.mail_gid,
				&saved_uid, &saved_gid);
	}

	/* set environment */
	n = 0;
	envp[n++] = g_strdup_printf("SENDER=%s@%s",
			msg->return_path->local_part,
			msg->return_path->domain);
	envp[n++] = g_strdup_printf("SENDER_DOMAIN=%s",
			msg->return_path->domain);
	envp[n++] = g_strdup_printf("SENDER_LOCAL=%s",
			msg->return_path->local_part);
	envp[n++] = g_strdup_printf("RECEIVED_HOST=%s",
			msg->received_host ? msg->received_host : "");

	envp[n++] = g_strdup_printf("RETURN_PATH=%s@%s",
			msg->return_path->local_part,
			msg->return_path->domain);
	envp[n++] = g_strdup_printf("DOMAIN=%s",
			ancestor->domain);

	envp[n++] = g_strdup_printf("LOCAL_PART=%s", ancestor->local_part);
	envp[n++] = g_strdup_printf("USER=%s", ancestor->local_part);
	envp[n++] = g_strdup_printf("LOGNAME=%s", ancestor->local_part);

	envp[n++] = g_strdup_printf("MESSAGE_ID=%s", msg->uid);
	envp[n++] = g_strdup_printf("QUALIFY_DOMAIN=%s", conf.host_name);

	envp[n] = NULL;

	old_signal = signal(SIGCHLD, SIG_DFL);

	out = peidopen(cmd, "w", envp, &pid, conf.mail_uid, conf.mail_gid);
	if (!out) {
		logwrite(LOG_ALERT, "could not open pipe '%s': %s\n",
				cmd, strerror(errno));
	} else {
		message_stream(out, msg, hdr_list, flags);

		fclose(out);

		waitpid(pid, &status, 0);

		if (WEXITSTATUS(status) != 0) {
			int exstat = WEXITSTATUS(status);
			logwrite(LOG_ALERT, "process returned %d (%s)\n",
					exstat, ext_strerror(1024 + exstat));
			errno = 1024 + exstat;
		} else if (WIFSIGNALED(status)) {
			logwrite(LOG_ALERT, "process got signal %d\n",
					WTERMSIG(status));
		} else
			ok = TRUE;

	}

	signal(SIGCHLD, old_signal);

	/* free environment */
	for (i = 0; i < n; i++) {
		g_free(envp[i]);
	}

	/* set uid and gid back */
	if (!conf.run_as_user) {
		set_euidgid(saved_uid, saved_gid, NULL, NULL);
	}

	return ok;
}
