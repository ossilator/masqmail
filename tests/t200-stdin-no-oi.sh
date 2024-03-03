#!/bin/sh

. lib.sh

TEST_HOST=localhost

send_mail_direct $LOGNAME@$TEST_HOST <<EOF
$(make_header)

$GREETING

..
there is a dot above (Yes, one and not two).

Fritz
EOF

verify_delivery
verify_content '^\.$'
