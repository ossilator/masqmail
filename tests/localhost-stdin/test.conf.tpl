# running as user is enough for testing purposes
run_as_user=true

# set debug level (0 = no debugging, 5 = very much, 6 = too much)
debug_level = 5

# deliver at once
do_queue = false

#
host_name="SMTP_HOST"

# we want to deliver a message to localhost
local_hosts="localhost"

# spool dir is the current directory
spool_dir="PWD/spool"

# deliver local mail into the current directory
mail_dir="PWD"

# log into the current directory
use_syslog=false
log_dir="PWD"

# relative paths to warn/failure message templates
errmsg_file="PWD/../../tpl/failmsg.tpl"
warnmsg_file="PWD/../../tpl/warnmsg.tpl"
