#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
configure_sink $SEND_USER

send_generic_mail -f $SEND_ADDR MASQMAIL/fake@$RECV_HOST

verify_local_delivery
verify_content "$ERROR"
