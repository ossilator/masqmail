#!/bin/sh

. lib.sh

TEST_HOST=localhost

send_mail_direct $LOGNAME@$TEST_HOST <<EOF
$(make_mail)
.
EOF

verify_delivery
