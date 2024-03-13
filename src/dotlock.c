// SPDX-FileCopyrightText: (C) 2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include <glib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "masqmail.h"
#include "dotlock.h"

gboolean
dot_lock(gchar *lock_name, gchar *hitch_name)
{
	gboolean ok = FALSE;
	int fd;

	fd = open(hitch_name, O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd != -1) {
		struct stat stat_buf;

		close(fd);
		link(hitch_name, lock_name);
		if (stat(hitch_name, &stat_buf) == 0) {
			if (stat_buf.st_nlink == 2) {
				unlink(hitch_name);
				ok = TRUE;
			} else {
				if (stat(lock_name, &stat_buf) == 0) {
					if ((time(NULL) - stat_buf.st_mtime) > MAX_LOCKAGE) {
						/* remove lock if uncredibly old */
						unlink(lock_name);

						link(hitch_name, lock_name);
						if (stat(hitch_name, &stat_buf) == 0) {
							if (stat_buf.st_nlink == 2) {
								unlink(hitch_name);
								ok = TRUE;
							}
						}
					}
				}
			}
		}
		if (!ok) {
			unlink(hitch_name);
		}
	} else
		logwrite(LOG_WARNING, "could not create lock file %s: %s\n", lock_name, strerror(errno));

	return ok;
}

gboolean
dot_unlock(gchar *lock_name)
{
	unlink(lock_name);

	return TRUE;
}
