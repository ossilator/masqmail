#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
configure_sink

send_generic_mail $RECV_ADDR

verify_local_delivery
