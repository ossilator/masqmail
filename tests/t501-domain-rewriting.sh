#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
configure_mailhost_relay
cat >> "$LOCAL_CONFIG" <<EOF

local_hosts = "blackhole.com; dogs.net"
EOF
cat >> "$ROUTE" <<EOF
map_h_mail_followup_to_addresses = "*: *@example.com"
EOF

send_mail $RECV_ADDR <<EOF
Mail-Followup-To: foo, bar@blackhole.com, Bite Me <baz@dogs.net>
$(make_generic_body)
EOF

verify_remote_delivery
verify_content '^Mail-Followup-To: foo@example\.com, bar@example\.com, Bite Me <baz@example\.com>$'
