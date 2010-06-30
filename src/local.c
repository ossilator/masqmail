/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <sys/wait.h>

#include "masqmail.h"
#include "peopen.h"

static void
message_stream(FILE * out, message * msg, GList * hdr_list, guint flags)
{
	time_t now = time(NULL);
	GList *node;

	if (flags & MSGSTR_FROMLINE) {
		fprintf(out, "From <%s@%s> %s", msg->return_path->local_part, msg->return_path->domain, ctime(&now));
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
append_file(message * msg, GList * hdr_list, gchar * user)
{
	struct passwd *pw;
	gboolean ok = FALSE;

	/* headers may be special for a local delivery */
	if (hdr_list == NULL)
		hdr_list = msg->hdr_list;

	if ((pw = getpwnam(user))) {
		uid_t saved_uid = geteuid();
		gid_t saved_gid = getegid();
		gboolean uid_ok = TRUE, gid_ok = TRUE;

		if (!conf.run_as_user) {
			uid_ok = (seteuid(0) == 0);
			if (uid_ok) {
				gid_ok = (setegid(conf.mail_gid) == 0);
				uid_ok = (seteuid(pw->pw_uid) == 0);
			}
		}

		DEBUG(5) debugf("running as euid %d, egid %d\n", geteuid(), getegid());

		if (uid_ok && gid_ok) {
			gchar *filename;
			FILE *out;

			filename = g_strdup_printf("%s/%s", conf.mail_dir, user);
			if ((out = fopen(filename, "a"))) {
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
					message_stream(out, msg, hdr_list, MSGSTR_FROMLINE | MSGSTR_FROMHACK);
					ok = TRUE;

					/* close when still user */
					fclose(out);
#ifdef USE_LIBLOCKFILE
					mailunlock();
#endif
				} else {
					fclose(out);
#ifdef USE_LIBLOCKFILE
					DEBUG(3) debugf("could not lock file %s: error %d\n", filename, err);
				}  /* XEmacs indenting convenience... */
#else
					DEBUG(3) debugf("could not lock file %s: %s\n", filename, strerror(errno));
				}
#endif
			} else {
				logwrite(LOG_ALERT, "could not open file %s: %s\n", filename, strerror(errno));
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
				/* FIXME: if this fails we HAVE to exit, because we shall not run
				   with some users id. But we do not return, and so this message
				   will not be finished, so the user will get the message again
				   next time a delivery is attempted... */
				logwrite(LOG_ALERT, "could not set back uid or gid after local delivery: %s\n", strerror(errno));
				logwrite(LOG_ALERT, "uid=%d, gid=%d, euid=%d, egid=%d, want = %d, %d\n",
				         getuid(), getgid(), geteuid(), getegid(), saved_uid, saved_gid);
				exit(EXIT_FAILURE);
			}
		} else {
			logwrite(LOG_ALERT, "could not set uid or gid for local delivery, uid = %d: %s\n", pw->pw_uid, strerror(errno));
		}
	} else {
		logwrite(LOG_ALERT, "could not find password entry for user %s\n", user);
		errno = ENOENT;  /* getpwnam does not set errno correctly */
	}

	return ok;
}

#ifdef ENABLE_MAILDIR
gboolean
maildir_out(message * msg, GList * hdr_list, gchar * user, guint flags)
{
	struct passwd *pw;
	gboolean ok = FALSE;

	/* headers may be special for a local delivery */
	if (hdr_list == NULL)
		hdr_list = msg->hdr_list;

	if ((pw = getpwnam(user))) {
		uid_t saved_uid = geteuid();
		gid_t saved_gid = getegid();
		gboolean uid_ok = TRUE, gid_ok = TRUE;

		if (!conf.run_as_user) {
			uid_ok = (seteuid(0) == 0);
			if (uid_ok) {
				gid_ok = (setegid(conf.mail_gid) == 0);
				uid_ok = (seteuid(pw->pw_uid) == 0);
			}
		}

		DEBUG(5) debugf("running as euid %d, egid %d\n", geteuid(), getegid());

		if (uid_ok && gid_ok) {
			char *path = g_strdup_printf("%s/Maildir", pw->pw_dir);
			struct stat statbuf;
			int ret;

			DEBUG(5) debugf("  path = %s\n", path);

			ok = TRUE;
			ret = stat(path, &statbuf);
			if (ret != 0) {
				ok = FALSE;
				if (errno == ENOENT) {
					logwrite(LOG_NOTICE, "directory %s does not exist, creating\n", path);
					if (mkdir(path, 0700) == 0)
						ok = TRUE;
				} else
					logwrite(LOG_ALERT, "stat of %s failed: %s\n", path, strerror(errno));
			}
			if (ok) {
				ok = FALSE;
				ret = stat(path, &statbuf);
				if (S_ISDIR(statbuf.st_mode)) {
					gchar *subdirs[] = { "tmp", "new", "cur" };
					int i;
					for (i = 0; i < 3; i++) {
						char *path1 = g_strdup_printf("%s/%s", path, subdirs[i]);
						ret = stat(path1, &statbuf);
						if (ret != 0) {
							if (errno == ENOENT) {
								logwrite(LOG_NOTICE, "directory %s does not exist, creating\n", path1);
								if (mkdir(path1, 0700) != 0)
									break;
							}
						}
						g_free(path1);
					}
					if (i == 3) {
						FILE *out;
						mode_t saved_mode = umask(066);
						/* the qmail style unique works only if delivering with different process.
						   We do not fork for each delivery, so our uid is more unique.
						   Hope it is compatible with all MUAs.
						 */
						gchar *filename = g_strdup_printf("%s/tmp/%s.%s", path, msg->uid, conf.host_name);

						DEBUG(5) debugf("filename = %s\n", filename);

						if ((out = fopen(filename, "w"))) {
							gchar *newname = g_strdup_printf("%s/new/%s.%s", path, msg->uid, conf.host_name);
							message_stream(out, msg, hdr_list, flags);
							ok = TRUE;
							if (fflush(out) == EOF)
								ok = FALSE;
							else if (fdatasync(fileno(out)) != 0) {
								if (errno != EINVAL)
									/* some fs do not support this..  I hope this also means that it is not necessary */
									ok = FALSE;
							}
							fclose(out);
							if (rename(filename, newname) != 0) {
								ok = FALSE;
								logwrite(LOG_ALERT, "moving %s to %s failed: %s", filename, newname, strerror(errno));
							}
							g_free(newname);
						}
						umask(saved_mode);
						g_free(filename);
					}
				} else {
					logwrite(LOG_ALERT, "%s is not a directory\n", path);
					errno = ENOTDIR;
				}
			}
			if (!conf.run_as_user) {
				uid_ok = (seteuid(0) == 0);
				if (uid_ok) {
					gid_ok = (setegid(saved_gid) == 0);
					uid_ok = (seteuid(saved_uid) == 0);
				}
			}
			if (!uid_ok || !gid_ok) {
				/* FIXME: if this fails we HAVE to exit, because we shall not run
				   with some users id. But we do not return, and so this message
				   will not be finished, so the user will get the message again
				   next time a delivery is attempted... */
				logwrite(LOG_ALERT, "could not set back uid or gid after local delivery: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			g_free(path);
		} else {
			logwrite(LOG_ALERT, "could not set uid or gid for local delivery, uid = %d: %s\n", pw->pw_uid, strerror(errno));
		}
	} else {
		logwrite(LOG_ALERT, "could not find password entry for user %s\n", user);
		errno = ENOENT;  /* getpwnam does not set errno correctly */
	}
	return ok;
}
#endif

gboolean
pipe_out(message * msg, GList * hdr_list, address * rcpt, gchar * cmd, guint flags)
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

	/* set uid and gid to the mail ids */
	if (!conf.run_as_user) {
		set_euidgid(conf.mail_uid, conf.mail_gid, &saved_uid, &saved_gid);
	}

	/* set environment */
	{
		gint i = 0;
		address *ancestor = addr_find_ancestor(rcpt);

		envp[i++] = g_strdup_printf("SENDER=%s@%s", msg->return_path->local_part, msg->return_path->domain);
		envp[i++] = g_strdup_printf("SENDER_DOMAIN=%s", msg->return_path->domain);
		envp[i++] = g_strdup_printf("SENDER_LOCAL=%s", msg->return_path->local_part);
		envp[i++] = g_strdup_printf("RECEIVED_HOST=%s", msg->received_host ? msg->received_host : "");

		envp[i++] = g_strdup_printf("RETURN_PATH=%s@%s", msg->return_path->local_part, msg->return_path->domain);
		envp[i++] = g_strdup_printf("DOMAIN=%s", ancestor->domain);

		envp[i++] = g_strdup_printf("LOCAL_PART=%s", ancestor->local_part);
		envp[i++] = g_strdup_printf("USER=%s", ancestor->local_part);
		envp[i++] = g_strdup_printf("LOGNAME=%s", ancestor->local_part);

		envp[i++] = g_strdup_printf("MESSAGE_ID=%s", msg->uid);
		envp[i++] = g_strdup_printf("QUALIFY_DOMAIN=%s", conf.host_name);

		envp[i] = NULL;
		n = i;
	}

	old_signal = signal(SIGCHLD, SIG_DFL);

	out = peidopen(cmd, "w", envp, &pid, conf.mail_uid, conf.mail_gid);
	if (out != NULL) {
		message_stream(out, msg, hdr_list, flags);

		fclose(out);

		waitpid(pid, &status, 0);

		if (WEXITSTATUS(status) != 0) {
			int exstat = WEXITSTATUS(status);
			logwrite(LOG_ALERT, "process returned %d (%s)\n", exstat, ext_strerror(1024 + exstat));
			errno = 1024 + exstat;
		} else if (WIFSIGNALED(status)) {
			logwrite(LOG_ALERT, "process got signal %d\n", WTERMSIG(status));
		} else
			ok = TRUE;

	} else
		logwrite(LOG_ALERT, "could not open pipe '%s': %s\n", cmd, strerror(errno));

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
