#!/bin/sh

. lib.sh

TEST_HOST=localhost

launch_server

prepare_relay
configure_relay_all
cat >> "$ROUTE" <<EOF
map_h_from_addresses = "foo: Dark Foo <fooish@example.com>"
map_h_reply_to_addresses = "bar: Bar Man <drink@example-fail.com>"
map_h_mail_followup_to_addresses = "baz: \"The Real Me\" <me@example.com>; bar: Bar Exam <admin@blackhole.com>"
map_return_path_addresses = "sendy: dummy@example.com"
expand_h_sender_address = true
EOF

# the excess headers verify the none/some/all replacement cases,
# giving particular attention to the last element.
run_masqmail -f sendy@$RELAY_HOST $LOGNAME@$TEST_HOST <<EOF
From: foo
Reply-To: bar
Mail-Followup-To: baz , list@example.com	,
	some@one
Mail-Followup-To: some@one, bar@$RELAY_HOST
Mail-Followup-To: some@one
Sender: garbage@nonsense.ork
Subject: Masqmail test: $TEST_NAME

$GREETING
EOF

verify_delivery
verify_content '^From: Dark Foo <fooish@example\.com>$'
verify_content '^Reply-To: Bar Man <drink@example-fail\.com>$'
verify_content '^Mail-Followup-To: \"The Real Me\" <me@example\.com>,list@example\.com,some@one$'
verify_content '^Mail-Followup-To: some@one,Bar Exam <admin@blackhole\.com>$'
verify_content '^Mail-Followup-To: some@one$'
verify_content '^Return-path: <dummy@example\.com>$'
verify_content '^Sender: dummy@example\.com$'
