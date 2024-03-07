#!/bin/sh

. lib.sh

TEST_HOST=localhost

launch_server

prepare_relay
cat >> "$CONFIG" <<EOF

local_hosts = "blackhole.com; dogs.net"
EOF
cat >> "$ROUTE" <<EOF
map_h_mail_followup_to_addresses = "*: *@example.com"
EOF

run_masqmail $LOGNAME@$TEST_HOST <<EOF
Mail-Followup-To: foo, bar@blackhole.com, Bite Me <baz@dogs.net>
Subject: Masqmail test: $TEST_NAME

$GREETING
EOF

verify_delivery
verify_content '^Mail-Followup-To: foo@example\.com, bar@example\.com, Bite Me <baz@example\.com>$'
