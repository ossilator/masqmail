#!/bin/sh

. lib.sh

TEST_HOST=localhost

launch_server

prepare_relay
configure_relay_all
cat >> "$ROUTE" <<EOF
map_outgoing_addresses = "$LOGNAME: Ty Coon <dummy@example.com>"
EOF

run_masqmail -f $LOGNAME@$RELAY_HOST $LOGNAME@$TEST_HOST <<EOF
From: $LOGNAME
Reply-To: $LOGNAME@$RELAY_HOST
Mail-Followup-To: $LOGNAME
Subject: Masqmail test: $TEST_NAME

$GREETING
EOF

verify_delivery
verify_content '^From: Ty Coon <dummy@example\.com>$'
verify_content '^Reply-To: Ty Coon <dummy@example\.com>$'
verify_content '^Mail-Followup-To: Ty Coon <dummy@example\.com>$'
verify_content '^Return-path: <dummy@example\.com>$'
