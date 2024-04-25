#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
configure_sink
SCRIPT=$OUT_DIR/receiver.sh
cat > "$SCRIPT" <<EOF
#!/bin/sh
cat >> "$LOCAL_BOX"
echo "Options: \$@" >> "$LOCAL_BOX"
EOF
chmod +x "$SCRIPT"
cat >> "$LOCAL_CONFIG" <<EOF
mda = "$SCRIPT received \$uid from \$return_path \"(\$ident on \$received_host)\" for \${rcpt_local}@\$rcpt_domain"
mda_users = $RECV_USER
EOF

send_generic_mail $RECV_ADDR

verify_local_delivery
