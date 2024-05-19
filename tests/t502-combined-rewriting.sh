#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
configure_mailhost_relay
configure_relay_all
cat >> "$ROUTE" <<EOF
map_outgoing_addresses = "$SEND_USER: Ty Coon <dummy@example.com>"
EOF

send_mail -f $SEND_USER@$RELAY_HOST $RECV_ADDR <<EOF
From: $SEND_USER
Sender: $SEND_USER
Reply-To: $SEND_USER@$RELAY_HOST
Mail-Followup-To: $SEND_USER
$(make_generic_body)
EOF

verify_remote_delivery
verify_content '^From: Ty Coon <dummy@example\.com>$'
verify_content '^Sender: Ty Coon <dummy@example\.com>$'
verify_content '^Reply-To: Ty Coon <dummy@example\.com>$'
verify_content '^Mail-Followup-To: Ty Coon <dummy@example\.com>$'
verify_content '^Return-path: <dummy@example\.com>$'
