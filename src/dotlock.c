/*  MasqMail
    Copyright (C) 2001 Oliver Kurth

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
dot_lock(gchar * lock_name, gchar * hitch_name)
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
dot_unlock(gchar * lock_name)
{
	unlink(lock_name);

	return TRUE;
}
