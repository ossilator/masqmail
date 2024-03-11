#!/bin/sh

. "$(dirname "$0")/lib.sh"

prepare_server
SERVER_ALIASES=$SERVER_DIR/aliases.conf
cat > "$SERVER_ALIASES" <<EOF
bobby@example.com: $RECV_USER
EOF
cat >> "$SERVER_CONFIG" <<EOF

globalias_file = "$SERVER_ALIASES"
local_addresses = "bobby@example.com"
EOF
start_server

make_config LOCAL
PIPE_BOX=$OUT_DIR/pipebox
touch "$PIPE_BOX"
SCRIPT=$OUT_DIR/receiver.sh
cat > "$SCRIPT" <<EOF
#!/bin/sh
cat >> "$PIPE_BOX"
EOF
chmod +x "$SCRIPT"
ALIASES=$LOCAL_DIR/aliases.conf
cat > "$ALIASES" <<EOF
foo: alice_123, bob_123, rob_123@localhost
alice_123: $RECV_USER
bob_123: bobby@example.com
rob_123: "|\"$SCRIPT\""
EOF
cat >> "$LOCAL_CONFIG" <<EOF

alias_file = "$ALIASES"
EOF
configure_mailhost_relay
configure_sink

send_mail foo <<EOF
From: $SEND_USER
To: foobar
$(make_generic_body)
EOF

verify_pipe_delivery()
{
	for i in $BACKOFF; do
		grep -q "^$GREETING\$" "$PIPE_BOX" && return 0
		sleep $i
	done
	echo "Expected content not found in pipe box." >&2
	return 1
}

verify_local_delivery
verify_pipe_delivery
verify_remote_delivery
