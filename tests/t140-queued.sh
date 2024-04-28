#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
configure_sink

send_generic_mail -odq $RECV_ADDR

verify_queue "^RT: <$RECV_ADDR>\$"

run_queue

verify_local_delivery
