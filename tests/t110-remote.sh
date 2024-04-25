#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config SERVER
configure_sink
configure_server ";localhost:$SERVER_PORT"
start_server

make_config LOCAL
configure_direct_relay
configure_relay_all

send_generic_mail $RECV_ADDR $RECV_USER@localhost

verify_remote_delivery 2
