// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
**
*/

#include "masqmail.h"

#ifdef USE_LIBLOCKFILE
#  include <maillock.h>
#else
#  include <fcntl.h>
#endif

#include <pwd.h>
#include <sysexits.h>
#include <sys/wait.h>
#include <sys/stat.h>

static gboolean
message_stream(FILE *out, message *msg, GList *hdr_list, guint flags)
{
	time_t now = time(NULL);
	GList *node;

	if (flags & MSGSTR_FROMLINE) {
		if (fprintf(out, "From %s %s", msg->return_path->address, ctime(&now)) < 0) {
			goto fail;
		}
	}

	foreach(hdr_list, node) {
		header *hdr = (header *) (node->data);
		if (fputs(hdr->header, out) == EOF) {
			goto fail;
		}
	}
	if (putc('\n', out) == EOF) {
		goto fail;
	}

	foreach(msg->data_list, node) {
		/* From hack: */
		if (flags & MSGSTR_FROMHACK) {
			if (strncmp(node->data, "From ", 5) == 0) {
				if (putc('>', out) == EOF) {
					goto fail;
				}
			}
		}
		if (fputs(node->data, out) == EOF) {
			goto fail;
		}
	}
	if (putc('\n', out) == EOF) {
		goto fail;
	}

	if (fflush(out) == EOF) {
		goto fail;
	}
	if (fdatasync(fileno(out)) && errno != EINVAL) {
		goto fail;
	}

	return TRUE;

  fail:
	logerrno(LOG_ERR, "could not write message %s", msg->uid);
	return FALSE;
}

gboolean
append_file(message *msg, GList *hdr_list, gchar *user)
{
	struct passwd *pw;
	gboolean ok = FALSE;
	gchar *filename;
	FILE *out;

	/* headers may be special for a local delivery */
	if (!hdr_list)
		hdr_list = msg->hdr_list;

	if (!conf.run_as_user) {
		if (!(pw = getpwnam(user))) {
			logwrite(LOG_ERR, "could not find password entry for user %s\n", user);
			errno = ENOENT;  /* getpwnam does not set errno correctly */
			return FALSE;
		}

		if (seteuid(pw->pw_uid) != 0) {
			logerrno(LOG_ERR, "could not set uid %u for local delivery", pw->pw_uid);
			return FALSE;
		}
	} else {
		// We allow arbitrary mailboxes, but we still need to
		// prevent escape from the designated directory.
		if (strchr(user, '/')) {
			logwrite(LOG_ERR, "invalid user name '%s'\n", user);
			errno = EINVAL;
			return FALSE;
		}
	}

	DEBUG(5) debugf("running as euid %u, egid %u\n", geteuid(), getegid());

	filename = g_strdup_printf("%s/%s", conf.mail_dir, user);
	if (!(out = fopen(filename, "a"))) {
		logerrno(LOG_ERR, "could not open file %s", filename);
	} else {
#ifdef USE_LIBLOCKFILE
		gchar *lockfile = g_strconcat(filename, ".lock", NULL);
		gint err;
		/* lock file using liblockfile */
		err = lockfile_create(lockfile, 3, 0);
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
			ok = message_stream(out, msg, hdr_list, MSGSTR_FROMLINE | MSGSTR_FROMHACK);

			/* close when still user */
			fclose(out);
#ifdef USE_LIBLOCKFILE
			lockfile_remove(lockfile);
#endif
		} else {
			fclose(out);
#ifdef USE_LIBLOCKFILE
			DEBUG(3) debugf("could not lock file %s: error %d\n",
					filename, err);
		}  /* XEmacs indenting convenience... */
		g_free(lockfile);
#else
			DEBUG(3) debugf("could not lock file %s: %s\n",
					filename, strerror(errno));
		}
#endif
	}
	g_free(filename);

	if (!conf.run_as_user && seteuid(conf.mail_uid) != 0) {
		/*
		**  FIXME: if this fails we HAVE to exit, because we shall
		**  not run with some users id. But we do not return, and so
		**  this message will not be finished, so the user will get
		**  the message again next time a delivery is attempted...
		*/
		logerrno(LOG_ERR, "could not set back uid after local delivery");
		DEBUG(1) debugf("uid=%u, euid=%u, want = %u\n",
		                getuid(), geteuid(), conf.mail_uid);
		exit(1);
	}
	return ok;
}

gboolean
pipe_out(message *msg, GList *hdr_list, recipient *rcpt, gchar *cmd, guint flags)
{
	gchar *envp[40];
	FILE *out;
	gboolean ok = FALSE;
	gint i, n;
	pid_t pid;
	int status;
	recipient *ancestor = addr_find_ancestor(rcpt);

	/* set environment */
	n = 0;
	envp[n++] = g_strdup_printf("RETURN_PATH=%s", msg->return_path->address);
	envp[n++] = g_strdup_printf("SENDER=%s",
			msg->return_path->address);
	envp[n++] = g_strdup_printf("SENDER_DOMAIN=%s",
			msg->return_path->domain);
	envp[n++] = g_strdup_printf("SENDER_LOCAL=%s",
			msg->return_path->local_part);
	envp[n++] = g_strdup_printf("RECEIVED_HOST=%s",
			msg->received_host ? msg->received_host : "");

	envp[n++] = g_strdup_printf("DOMAIN=%s", ancestor->address->domain);
	envp[n++] = g_strdup_printf("LOCAL_PART=%s", ancestor->address->local_part);
	envp[n++] = g_strdup_printf("USER=%s", ancestor->address->local_part);
	envp[n++] = g_strdup_printf("LOGNAME=%s", ancestor->address->local_part);

	envp[n++] = g_strdup_printf("MESSAGE_ID=%s", msg->uid);
	envp[n++] = g_strdup_printf("QUALIFY_DOMAIN=%s", conf.host_name);

	envp[n] = NULL;

	gchar **argv;
	GError *gerr = NULL;
	if (!g_shell_parse_argv(cmd, NULL, &argv, &gerr)) {
		loggerror(LOG_ERR, gerr, "failed to parse pipe command");
		goto fail;
	}
	int stdin_fd;
	gboolean cldok = g_spawn_async_with_pipes(
			NULL /* workdir */, argv, envp,
			G_SPAWN_DO_NOT_REAP_CHILD |
					G_SPAWN_CHILD_INHERITS_STDOUT | G_SPAWN_CHILD_INHERITS_STDERR,
			NULL, NULL, /* child setup */
			&pid, &stdin_fd, NULL /* out */, NULL /* err */, &gerr);
	if (!cldok) {
		loggerror(LOG_ERR, gerr, "failed to launch pipe command '%s'", cmd);
	} else {
		out = fdopen(stdin_fd, "w");
		ok = message_stream(out, msg, hdr_list, flags);

		fclose(out);

		waitpid(pid, &status, 0);

		if (WEXITSTATUS(status) != 0) {
			int exstat = WEXITSTATUS(status);
			logwrite(LOG_ERR, "process '%s' returned %d (%s)\n",
			         cmd, exstat, sysexit_str(exstat));
			errno = (exstat == EX_TEMPFAIL) ? EAGAIN : ECANCELED;
			ok = FALSE;
		} else if (WIFSIGNALED(status)) {
			logwrite(LOG_ERR, "process '%s' got signal %d\n",
			         cmd, WTERMSIG(status));
			errno = ECANCELED;
			ok = FALSE;
		}
	}

  fail:
	/* free environment */
	for (i = 0; i < n; i++) {
		g_free(envp[i]);
	}

	return ok;
}
