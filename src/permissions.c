/*  MasqMail
    Copyright (C) 2000 Oliver Kurth

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

#include <pwd.h>
#include <grp.h>

#include "masqmail.h"

/* is there really no function in libc for this? */
gboolean
is_ingroup(uid_t uid, gid_t gid)
{
	struct group *grent = getgrgid(gid);
	struct passwd *pwent = getpwuid(uid);
	char *entry;
	int i = 0;

	if (!grent) {
		return FALSE;
	}
	if (!pwent) {
		return FALSE;
	}
	/* check primary group */
	if (pwent->pw_gid == gid) {
		return TRUE;
	}
	/* check secondary groups */
	while ((entry = grent->gr_mem[i++])) {
		if (strcmp(pwent->pw_name, entry) == 0)
			return TRUE;
	}
	return FALSE;
}

gboolean
is_privileged_user(uid_t uid)
{
	/* uncomment these lines if you need the `uucp' group to be trusted too
	struct group* grent = getgrnam("uucp");

	if (is_ingroup(uid, grent->gr_gid)) {
		return TRUE;
	}
	*/

	return (uid == 0) || (uid == conf.mail_uid) || (is_ingroup(uid, conf.mail_gid));
}

void
set_euidgid(gint uid, gint gid, uid_t * old_uid, gid_t * old_gid)
{
	if (old_uid)
		*old_uid = geteuid();
	if (old_gid)
		*old_gid = getegid();

	seteuid(0);

	if (setegid(gid) != 0) {
		logwrite(LOG_ALERT, "could not change gid to %d: %s\n", gid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (seteuid(uid) != 0) {
		logwrite(LOG_ALERT, "could not change uid to %d: %s\n", uid, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void
set_identity(uid_t old_uid, gchar * task_name)
{
	if (!conf.run_as_user) {
		if (!is_privileged_user(old_uid)) {
			fprintf(stderr, "must be root, %s or in group %s for %s.\n", DEF_MAIL_USER, DEF_MAIL_GROUP, task_name);
			exit(EXIT_FAILURE);
		}

		set_euidgid(conf.mail_uid, conf.mail_gid, NULL, NULL);
	}
}
