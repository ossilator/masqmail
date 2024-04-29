#!/bin/sh

. "$(dirname "$0")/lib.sh"

make_config
configure_sink

send_mail -oi $RECV_ADDR <<EOF
$(make_generic_head)
$(make_generic_body)

.
there is a dot above.

Fritz
EOF

verify_local_delivery
verify_content '^\.$'
