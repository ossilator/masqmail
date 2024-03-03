#!/bin/sh

. lib.sh

TEST_HOST=localhost

send_mail_direct -oi $LOGNAME@$TEST_HOST <<EOF
$(make_header)

$GREETING

.
there is a dot above.

Fritz
EOF

verify_delivery
verify_content '^\.$'
