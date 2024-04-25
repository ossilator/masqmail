#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config SERVER
configure_sink

make_config LOCAL
configure_route <<EOF
wrapper = "\"$MASQMAIL\" -C \"$SERVER_CONFIG\" -bs"
EOF
configure_relay_all

send_generic_mail $RECV_ADDR $RECV_USER@localhost

verify_remote_delivery 2
