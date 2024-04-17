#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
ROUTE=$LOCAL_DIR/test.route
cat > "$ROUTE" <<EOF
wrapper = "/bin/false"
EOF
cat >> "$LOCAL_CONFIG" <<EOF

permanent_routes = "$ROUTE"
EOF
configure_sink $SEND_USER

send_generic_mail -f $SEND_ADDR fake@example.com

verify_queue "^MF:<$SEND_ADDR>\$"

ts=$(sed -n -e 's/^TR: \([0-9][0-9]*\)/\1/p' < "$SPOOLED")

# first fake the time received to force a warning mail.
sed -e "s/^TR:.*/TR: $((ts - 4000))/" "$SPOOLED" > "$SPOOLED.new"
mv "$SPOOLED.new" "$SPOOLED"
run_queue
verify_content "$WARNING"

# then repeat to verify that no second warning is sent right away.
run_queue
verify_content "$WARNING"

# then back up some more to get the second warning.
# the time of the last warning also needs adjustment.
sed -e "s/^TR:.*/TR: $((ts - 20000))/" \
    -e "s/^TW:.*/TW: $((ts - 16000))/" "$SPOOLED" > "$SPOOLED.new"
mv "$SPOOLED.new" "$SPOOLED"
run_queue
verify_content "$WARNING" 2

# finally force the error bounce.
sed -e "s/^TR:.*/TR: $((ts - 350000))/" \
    -e "s/^TW:.*/TW: $((ts - 330000))/" "$SPOOLED" > "$SPOOLED.new"
mv "$SPOOLED.new" "$SPOOLED"
run_queue
verify_content "$ERROR"
