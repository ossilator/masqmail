#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
configure_mailhost_relay
configure_relay_all
cat >> "$ROUTE" <<EOF
map_h_from_addresses = "foo: Dark Foo <fooish@example.com>"
map_h_reply_to_addresses = "bar: Bar Man <drink@example-fail.com>"
map_h_mail_followup_to_addresses = "baz: \"The Real Me\" <me@example.com>; bar: Bar Exam <admin@blackhole.com>"
map_return_path_addresses = "sendy: dummy@example.com"
EOF

# the excess headers verify the none/some/all replacement cases,
# giving particular attention to the last element.
send_mail -f sendy@$RELAY_HOST $RECV_ADDR <<EOF
From: foo
Reply-To: bar
Mail-Followup-To: some@one, bar@$RELAY_HOST
Mail-Followup-To: some@one, other@two.me, bar@$RELAY_HOST
Mail-Followup-To: baz , list@example.com	,
	some@one
Mail-Followup-To: some@one
Mail-Followup-To: some@one,other@two.me
$(make_generic_body)
EOF

verify_remote_delivery
verify_content '^From: Dark Foo <fooish@example\.com>$'
verify_content '^Reply-To: Bar Man <drink@example-fail\.com>$'
verify_content '^Mail-Followup-To: some@one, Bar Exam <admin@blackhole\.com>$'
verify_content '^Mail-Followup-To: some@one, other@two.me, Bar Exam <admin@blackhole\.com>$'
verify_content '^Mail-Followup-To: \"The Real Me\" <me@example\.com>, list@example\.com	,$'
verify_content '^	some@one$'
verify_content '^Mail-Followup-To: some@one$'
verify_content '^Mail-Followup-To: some@one,other@two.me$'
verify_content '^Return-path: <dummy@example\.com>$'
