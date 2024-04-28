#!/bin/sh

SERVER_HOST=localhost

. "$(dirname "$0")/lib.sh"

make_config
configure_mailhost_relay
configure_relay_all

send_generic_mail $RECV_ADDR
