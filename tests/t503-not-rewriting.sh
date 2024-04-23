#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
configure_mailhost_relay
configure_relay_all
cat >> "$ROUTE" <<EOF
map_outgoing_addresses = "$SEND_USER: Ty Coon <dummy@example.com>"
EOF

send_mail -f $SEND_ADDR $RECV_ADDR <<EOF
From: $SEND_ADDR
$(make_generic_body)
EOF

verify_remote_delivery
verify_content "^From: $SEND_ADDR\$"
verify_content "^Return-path: <$SEND_ADDR>\$"
