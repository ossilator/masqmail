#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
configure_direct_relay
configure_relay_all

send_generic_mail $RECV_ADDR $RECV_USER@localhost

verify_remote_delivery

# one too much, because non_rcpt_list duplicates rcpt_list entries
verify_queue "^RT:X<$RECV_ADDR>\$" 2
verify_queue "^RT: <$RECV_USER@localhost>\$"

shutdown_server
sed -e "s/^\\(listen_addresses =\\) .*/\\1 localhost:$SERVER_PORT/" "$SERVER_CONFIG" > "$SERVER_CONFIG.new"
mv "$SERVER_CONFIG.new" "$SERVER_CONFIG"
start_server

run_queue

verify_remote_delivery 2
