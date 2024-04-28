#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
configure_sink
SEND_BOX=$LOCAL_DIR/mail/$SEND_USER
touch "$SEND_BOX"
ALIASES=$LOCAL_DIR/aliases.conf
cat > "$ALIASES" <<EOF
foo: $RECV_USER
bar: $RECV_USER, bar
baz: $RECV_USER, bak
bak: $RECV_USER, bogus@
EOF
cat >> "$LOCAL_CONFIG" <<EOF

alias_file = "$ALIASES"
EOF

send_generic_mail -f $SEND_ADDR $RECV_USER foo bar baz

verify_local_delivery 2

verify_local_delivery 1 "$SEND_BOX"
verify_content "$ERROR" 1
verify_content "^	<bar@$RECV_HOST>" 1
verify_content "^	<baz@$RECV_HOST>" 1
