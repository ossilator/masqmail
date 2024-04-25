#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
configure_mailhost_relay
configure_relay_all

send_generic_mail -odq $RECV_ADDR
send_generic_mail -odq $RECV_ADDR
run_queue

verify_remote_delivery 2
