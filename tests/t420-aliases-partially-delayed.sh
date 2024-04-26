#!/bin/sh

. "$(dirname "$0")/lib.sh"

launch_server

make_config LOCAL
ALIASES=$LOCAL_DIR/aliases.conf
cat > "$ALIASES" <<EOF
foo: $RECV_ADDR, $RECV_USER@localhost
EOF
cat >> "$LOCAL_CONFIG" <<EOF

alias_file = "$ALIASES"
local_addresses = foo@$HOST_NAME
EOF
configure_direct_relay
configure_relay_all

send_generic_mail foo

verify_remote_delivery

verify_queue "^RT: <foo@$HOST_NAME>\$"
verify_queue "^RT:X<$RECV_ADDR>\$"
verify_queue "^RT: <$RECV_USER@localhost>\$" 0

shutdown_server
sed -e "s/^\\(listen_addresses =\\) .*/\\1 localhost:$SERVER_PORT/" "$SERVER_CONFIG" > "$SERVER_CONFIG.new"
mv "$SERVER_CONFIG.new" "$SERVER_CONFIG"
start_server

run_queue

verify_remote_delivery 2
