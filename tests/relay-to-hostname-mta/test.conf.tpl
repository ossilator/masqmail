
# this is just for testing. In real life it does not make much sense:
run_as_user=true

# set debug level (0 = no debugging, 5 = very much, 6 = too much)
# can also be set with the -d option on the cmd line
debug_level = 5

do_queue = false

# The name with which MasqMail identifies itself to others:
host_name="MASQMAIL-TEST"

# where MasqMail stores its spool files and other stuff:
spool_dir="PWD"

# where local mail will be written to:
mail_dir="PWD"

# use syslogd for logs?
use_syslog=false

# directory for log files if not using syslogd:
log_dir="PWD"

online_routes.test = "PWD/test.route"

errmsg_file="PWD/../../tpl/failmsg.tpl"
warnmsg_file="PWD/../../tpl/warnmsg.tpl"

online_detect = "file"
online_file = "PWD/online"

