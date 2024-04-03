#!/bin/sh
# SPDX-FileCopyrightText: (C) 2024 Oswald Buddenhagen <oswald.buddenhagen@gmx.de>
# SPDX-License-Identifier: ISC

cd "$(dirname "$0")"

if test -e .git; then
	mb=$(git merge-base HEAD "@{upstream}" 2> /dev/null)
	if test -z "$mb"; then
		# we presume that a failure to find a merge base means no upstream.
		# and no upstream may mean detached head in the middle of a rebase
		br=$(git branch | sed -n -e 's/^\* (no branch, rebasing \([^\)]*\))$/\1/p')
		if test -n "$br"; then
			mb=$(git merge-base HEAD "$br@{upstream}" 2> /dev/null)
		fi
	fi
	if test -z "$mb"; then
		# still no upstream, so just describe HEAD as-is.
		gver=$(git describe --tags HEAD)
	else
		# find out whether we have local work, and if so, collapse it into
		# a single suffix. otherwise, we'd cause pointless rebuilds during
		# development.
		gver=$(git describe --tags $mb)
		lcl=$(git rev-list -n 1 $mb..HEAD)
		if test -n "$lcl"; then
			gver="$gver-plus"
		fi
	fi
	echo "${gver#v}"
else
	sed -n -e '/^[0-9]\.[0-9]\{1,\}\.[0-9]\{1,\}/{p;q}' NEWS
fi
