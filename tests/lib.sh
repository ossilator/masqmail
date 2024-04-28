# SPDX-FileCopyrightText: (C) 1999 Oliver Kurth
# SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
# SPDX-FileCopyrightText: (C) 2024 Oswald Buddenhagen <oswald.buddenhagen@gmx.de>
# SPDX-License-Identifier: ISC

set -e

TEST_NAME=${0##*/}
TEST_NAME=${TEST_NAME%.sh}

TEST_DIR=$(cd "$(dirname "$0")"; pwd)
TOP_SRC_DIR=${TEST_DIR%/*}

BUILD_DIR=$PWD
TOP_BUILD_DIR=${BUILD_DIR%/*}

OUT_BASE=$BUILD_DIR/out
OUT_DIR=$OUT_BASE/$TEST_NAME

MASQMAIL=$TOP_BUILD_DIR/src/masqmail

HOST_NAME=$(hostname)

RELAY_HOST="MASQMAIL-TEST"

SERVER_HOST=${SERVER_HOST:-$HOST_NAME}

RECV_USER=${RECV_USER:-$LOGNAME}
RECV_HOST=${RECV_HOST:-$HOST_NAME}
RECV_ADDR=$RECV_USER@$RECV_HOST

SEND_USER=${SEND_USER:-$LOGNAME}
SEND_HOST=${SEND_HOST:-$RECV_HOST}
SEND_ADDR=$SEND_USER@$SEND_HOST

run_masqmail()
{
	"$MASQMAIL" -C "$@"
}

send_mail()
{
	run_masqmail "$LOCAL_CONFIG" "$@"
}

make_config()
{
	CURR=${1:-LOCAL}
	local dir=$OUT_DIR${1:+/$(echo "$1" | tr '[A-Z]' '[a-z]')}
	local cfg=$dir/masqmail.conf
	eval ${CURR}_DIR=\$dir
	eval ${CURR}_CONFIG=\$cfg
	mkdir -p "$dir"
	cat > "$cfg" <<EOF
# because we are running a non-installed executable
errmsg_file = "$TOP_SRC_DIR/tpl/failmsg.tpl"
warnmsg_file = "$TOP_SRC_DIR/tpl/warnmsg.tpl"

# running as user is enough for testing purposes
run_as_user = true

debug_level = 6
use_syslog = false
log_dir = "$dir"

spool_dir = "$dir/spool"
lock_dir = "$dir/locks"
do_queue = false
EOF
}

configure_sink()
{
	eval local dir=\$${CURR}_DIR/mail
	CURR_BOX=$dir/${1:-$RECV_USER}
	eval ${CURR}_BOX=\$CURR_BOX
	eval local cfg=\$${CURR}_CONFIG
	mkdir "$dir"
	touch "$CURR_BOX"
	cat >> "$cfg" <<EOF

host_name = "$HOST_NAME"

mail_dir = "$dir"
EOF
}

configure_route()
{
	ROUTE=$LOCAL_DIR/test.route
	cat > "$ROUTE"
	cat >> "$LOCAL_CONFIG" <<EOF

permanent_routes = "$ROUTE"
EOF
}

configure_mailhost_relay()
{
	configure_route <<EOF
mail_host = "$SERVER_HOST"
resolve_list = byname
EOF
}

configure_relay_all()
{
	cat >> "$LOCAL_CONFIG" <<EOF

# identify with some name that is *not* the one of our machine.
host_name = "$RELAY_HOST"
EOF
}

make_generic_head()
{
	cat <<EOF
From: Fritz Meier <$SEND_ADDR>
To: "Alice G. Smith" <$RECV_ADDR>
EOF
}

GREETING="Hello There!"

make_generic_body()
{
	cat <<EOF
Subject: MasqMail test: $TEST_NAME

$GREETING
EOF
}

send_generic_mail()
{
	send_mail "$@" <<EOF
$(make_generic_head)
$(make_generic_body)
EOF
}

if [ ! -d "$OUT_BASE" ]; then
	tmp=$(mktemp -d)
	# we race with other instances here
	ln -snf "$tmp" "$OUT_BASE" || rmdir "$tmp"
else
	rm -rf "$OUT_DIR"/*
fi

mkdir -p "$OUT_DIR"
