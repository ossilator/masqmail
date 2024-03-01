#!/bin/sh

. lib.sh

TEST_HOST=localhost

send_mail_relay $LOGNAME@$TEST_HOST <<EOF
$(make_mail)
.
EOF

sleep .5
