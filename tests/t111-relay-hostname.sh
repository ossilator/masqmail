#!/bin/sh

. lib.sh

TEST_HOST=$HOST_NAME

send_mail_relay $LOGNAME@$TEST_HOST <<EOF
$(make_mail)
.
EOF
