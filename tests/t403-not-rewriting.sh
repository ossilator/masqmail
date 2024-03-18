#!/bin/sh

. lib.sh

TEST_HOST=localhost

launch_server

prepare_relay
configure_relay_all
cat >> "$ROUTE" <<EOF
map_outgoing_addresses = "$LOGNAME: Ty Coon <dummy@example.com>"
EOF

run_masqmail -f $LOGNAME@$TEST_HOST $LOGNAME@$TEST_HOST <<EOF
From: $LOGNAME@$TEST_HOST
Subject: Masqmail test: $TEST_NAME

$GREETING
EOF

verify_delivery
verify_content "^From: $LOGNAME@$TEST_HOST\$"
verify_content "^Return-path: <$LOGNAME@$TEST_HOST>\$"
