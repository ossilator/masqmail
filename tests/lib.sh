# SPDX-FileCopyrightText: (C) 1999 Oliver Kurth
# SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
# SPDX-FileCopyrightText: (C) 2024 Oswald Buddenhagen <oswald.buddenhagen@gmx.de>
# SPDX-License-Identifier: ISC

set -e

TEST_NAME=${0##*/}
TEST_NAME=${TEST_NAME%.sh}

TEST_DIR=$(cd $(dirname "$0"); pwd)

# defaults if nothing passed by the makefile
BUILD_DIR=${BUILD_DIR:-$TEST_DIR}
TOP_SRC_DIR=${TOP_SRC_DIR:-${TEST_DIR%/*}}
TOP_BUILD_DIR=${TOP_BUILD_DIR:-$TOP_SRC_DIR}

OUT_BASE=$TEST_DIR/out
OUT_DIR=$OUT_BASE/$TEST_NAME

MASQMAIL=$TOP_BUILD_DIR/src/masqmail

HOST_NAME=$(hostname)

RELAY_HOST="MASQMAIL-TEST"

run_masqmail()
{
	# the trailing '|| return' suppresses 'set -e' here.
	$MASQMAIL -C "$CONFIG" "$@" || return
}

make_config()
{
	CURR_DIR=$1
	mkdir -p "$1"
	CONFIG=$1/masqmail.conf
	cat > "$CONFIG" <<EOF
# because we are running a non-installed executable
errmsg_file = "$TOP_SRC_DIR/tpl/failmsg.tpl"
warnmsg_file = "$TOP_SRC_DIR/tpl/warnmsg.tpl"

# running as user is enough for testing purposes
run_as_user=true

debug_level = 6
use_syslog = false
log_dir = "$1"

spool_dir = "$1/spool"
lock_dir = "$1/locks"
do_queue = false
EOF
}

configure_sink()
{
	MAIL_DIR=$CURR_DIR/mail
	mkdir "$MAIL_DIR"
	MAIL_BOX=$MAIL_DIR/$LOGNAME
	touch "$MAIL_BOX"
	cat >> "$CONFIG" <<EOF

host_name = "$HOST_NAME"

mail_dir = "$MAIL_DIR"
EOF
}

send_mail_direct()
{
	make_config "$OUT_DIR"
	configure_sink
	run_masqmail "$@"
}

configure_relay()
{
	ROUTE=$CURR_DIR/test.route
	cat > "$ROUTE" <<EOF
mail_host = "$TEST_HOST"
resolve_list = byname
EOF
	cat >> "$CONFIG" <<EOF

permanent_routes = "$ROUTE"
EOF
}

prepare_relay()
{
	make_config "$OUT_DIR"
	configure_relay
}

configure_relay_all()
{
	cat >> "$CONFIG" <<EOF

# identify with some name that is *not* the one of our machine.
host_name = "$RELAY_HOST"
EOF
}

send_mail_relay()
{
	prepare_relay
	configure_relay_all
	run_masqmail "$@"
}

make_header()
{
	addr="\"Fritz Meier\" <$LOGNAME@$TEST_HOST>"
	cat <<EOF
From: $addr
To: $addr
Subject: Masqmail test: $TEST_NAME
EOF
}

GREETING="Hallo Fritz!"

make_mail()
{
	make_header
	echo
	echo "$GREETING"
}

if [ ! -d "$OUT_BASE" ]; then
	tmp=$(mktemp -d)
	# we race with other instances here
	ln -snf "$tmp" "$OUT_BASE" || rmdir "$tmp"
else
	rm -rf "$OUT_DIR"/*
fi

mkdir -p "$OUT_DIR"
