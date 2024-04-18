# SPDX-FileCopyrightText: (C) 1999 Oliver Kurth
# SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
# SPDX-FileCopyrightText: (C) 2024 Oswald Buddenhagen <oswald.buddenhagen@gmx.de>
# SPDX-License-Identifier: ISC

set -e

TEST_NAME=${0##*/}
TEST_NAME=${TEST_NAME%.sh}

TEST_IDX=${TEST_NAME%%-*}
TEST_IDX=${TEST_IDX#t}

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
SERVER_PORT=$((40000 + $TEST_IDX))

RECV_USER=${RECV_USER:-alice}
RECV_HOST=${RECV_HOST:-$HOST_NAME}
RECV_ADDR=$RECV_USER@$RECV_HOST

SEND_USER=${SEND_USER:-fritz}
SEND_HOST=${SEND_HOST:-$RECV_HOST}
SEND_ADDR=$SEND_USER@$SEND_HOST

BACKOFF=".1 .2 .4 .8 1.6 3.2"

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

host_name = "$HOST_NAME"
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

mail_dir = "$dir"
EOF
}

configure_server()
{
	cat >> "$SERVER_CONFIG" <<EOF

listen_addresses = $SERVER_HOST:$SERVER_PORT$1

pid_dir = "$SERVER_DIR"
EOF
}

prepare_server()
{
	make_config SERVER
	configure_sink
	configure_server
}

shutdown_server()
{
	kill $SERVER_PID
	for i in $BACKOFF; do
		sleep $i
		kill -0 $SERVER_PID 2> /dev/null || return 0
	done
	kill -9 $SERVER_PID 2> /dev/null || return 0
	sleep .1
}

start_server()
{
	run_masqmail "$SERVER_CONFIG" -bd "$@"
	SERVER_PID=$(cat "$SERVER_DIR/masqmail.pid")
	trap shutdown_server EXIT
}

launch_server()
{
	prepare_server
	start_server "$@"
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
mail_host = "$SERVER_HOST:$SERVER_PORT"
resolve_list = byname
EOF
}

configure_relay_all()
{
	cat >> "$LOCAL_CONFIG" <<EOF

# all mail should go through the route. thus we counter-factually
# declare that our host is not local.
local_hosts = "$RELAY_HOST"
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

eval_delivery()
{
	if [ $1 -lt $2 ]; then
		echo "Mail was not delivered correctly to ${3#$TEST_DIR/}." >&2
		return 1
	fi
	if [ $1 -gt $2 ]; then
		echo "Excess mail delivered to ${3#$TEST_DIR/}." >&2
		return 1
	fi
	CURR_BOX=$3
	return 0
}

verify_local_delivery()
{
	local count=${1:-1}
	local box=${2:-$LOCAL_BOX}
	local num=$(grep -c "^$GREETING\$" "$box" || true)
	eval_delivery $num $count "$box"
}

verify_remote_delivery()
{
	local count=${1:-1}
	local box=${2:-$SERVER_BOX}
	local got=false
	for i in $BACKOFF; do
		sleep $i
		local num=$(grep -c "^$GREETING\$" "$box" || true)
		[ $num -gt $count ] && break
		$got && break
		[ $num -ge 1 ] && got=true
	done
	eval_delivery $num $count "$box"
}

verify_content()
{
	local count=${2:-1}
	local box=${3:-$CURR_BOX}
	local num=$(grep -c "$1" "$box" || true)
	[ $num -eq $count ] && return 0
	echo "Got $num instead of $count occurrence(s) of '$1' in ${box#$TEST_DIR/}." >&2
	return 1
}

if [ ! -d "$OUT_BASE" ]; then
	tmp=$(mktemp -d)
	# we race with other instances here
	ln -snf "$tmp" "$OUT_BASE" || rmdir "$tmp"
else
	rm -rf "$OUT_DIR"/*
fi

mkdir -p "$OUT_DIR"
