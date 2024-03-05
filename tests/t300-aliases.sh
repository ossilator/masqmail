#!/bin/sh

. lib.sh

TEST_HOST=localhost

prepare_server
SRV_ALIASES=$CURR_DIR/aliases.conf
cat > "$SRV_ALIASES" <<EOF
bobby@example.com: $LOGNAME
EOF
cat >> "$CONFIG" <<EOF

globalias_file = "$SRV_ALIASES"
local_addresses = "bobby@example.com"
EOF
start_server
SERVER_BOX=$MAIL_BOX

prepare_relay
configure_sink
PIPEBOX=$OUT_DIR/pipebox
touch "$PIPEBOX"
SCRIPT=$OUT_DIR/receiver.sh
cat > "$SCRIPT" <<EOF
#!/bin/sh
cat >> "$PIPEBOX"
EOF
chmod +x "$SCRIPT"
ALIASES=$CURR_DIR/aliases.conf
cat > "$ALIASES" <<EOF
foo: alice_123, bob_123, rob_123@localhost
alice_123: $LOGNAME
bob_123: bobby@example.com
rob_123: "|$SCRIPT"
EOF
cat >> "$CONFIG" <<EOF

alias_file = "$ALIASES"
EOF

run_masqmail foo <<EOF
From: $LOGNAME
To: foobar
Subject: Masqmail test: $TEST_NAME

$GREETING
EOF

verify_pipe_delivery()
{
	for i in $BACKOFF; do
		grep -q "^$GREETING\$" "$PIPEBOX" && return 0
		sleep $i
	done
	echo "Expected content not found in pipe box." >&2
	return 1
}

verify_delivery
verify_pipe_delivery
verify_delivery "$SERVER_BOX"
