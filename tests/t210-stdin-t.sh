#!/bin/sh

. lib.sh

TEST_HOST=localhost

send_mail_direct -t <<EOF
$(make_mail)
.
EOF

verify_delivery
