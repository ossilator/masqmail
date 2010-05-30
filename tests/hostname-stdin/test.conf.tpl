# Example configuration for MasqMail
# Copyright (C) 1999 Oliver Kurth


# this is just for testing. In real life it does not make much sense:
run_as_user=true

# set debug level (0 = no debugging, 5 = very much, 6 = too much)
# can also be set with the -d option on the cmd line
debug_level = 5

do_queue = false

# The name with which MasqMail identifies itself to others:
host_name="SMTP_HOST"

# Hosts considered local:
local_hosts="SMTP_HOST"

# Nets considered local, for immediate delivery attempts:
# ALL hosts not included in either local_host or local_nets are
# considered to be 'outside', meaning that messages to them will be queued
#local_nets="SMTP_HOST"

# accept connections on these interfaces:
#listen_addresses="localhost:2525"

# where MasqMail stores its spool files and other stuff:
#spool_dir="/var/spool/masqmail"
spool_dir="PWD"

# where local mail will be written to:
mail_dir="PWD"

# use syslogd for logs?
use_syslog=false

# directory for log files if not using syslogd:
log_dir="PWD"
