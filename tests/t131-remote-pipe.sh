#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config SERVER
configure_sink

make_config LOCAL
configure_route <<EOF
pipe = "$MASQMAIL -C $SERVER_CONFIG -bm -f\$return_path \${rcpt}"
EOF
configure_relay_all

send_generic_mail $RECV_ADDR

verify_remote_delivery
