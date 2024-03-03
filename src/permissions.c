// SPDX-FileCopyrightText: (C) 2000 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <pwd.h>
#include <grp.h>

/* is there really no function in libc for this? */
static gboolean
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
is_privileged_user(void)
{
	if (conf.run_as_user) {
		return TRUE;
	}

	uid_t uid = conf.orig_uid;

	/* uncomment these lines if you need the `uucp' group to be trusted too
	struct group *grent = getgrnam("uucp");

	if (is_ingroup(uid, grent->gr_gid)) {
		return TRUE;
	}
	*/

	return (uid == 0) || (uid == conf.mail_uid) || (is_ingroup(uid, conf.mail_gid));
}

void
verify_privileged_user(gchar *task_name)
{
	if (!conf.run_as_user && !is_privileged_user()) {
		fprintf(stderr, "must be root, %s or in group %s for %s.\n", DEF_MAIL_USER, DEF_MAIL_GROUP, task_name);
		exit(1);
	}
}

static void
set_euid(gint uid)
{
	if (!conf.run_as_user && seteuid(uid) != 0) {
		logwrite(LOG_ERR, "could not change uid to %d: %s\n",
		         uid, strerror(errno));
		exit(1);
	}
}

void
acquire_root(void)
{
	set_euid(0);
}

void
drop_root(void)
{
	set_euid(conf.mail_uid);
}
