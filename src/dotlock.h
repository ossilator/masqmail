// SPDX-FileCopyrightText: (C) 2001 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#define MAX_LOCKAGE 300

gboolean dot_lock(gchar *lock_name, gchar *hitch_name);
gboolean dot_unlock(gchar *lock_name);
