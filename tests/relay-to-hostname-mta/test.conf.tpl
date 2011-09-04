# running as user is enough for testing purposes
run_as_user=true

# set debug level (0 = no debugging, 5 = very much, 6 = too much)
debug_level = 5

# deliver at once
do_queue = false

# identify with some name that is *not* the one of the our machine
# maybe we should not define a name at all, but this may lead to
# problems. Could be we even need a FQDN here.
host_name="MASQMAIL-TEST"

# we want to deliver through a route named `test' to a local MTA
# thus we do not define any hosts as local. All mail should go through
# the route.
permanent_routes = "PWD/test.route"


# spool files in the current directory
spool_dir="PWD"

# deliver local mails into the current directory
mail_dir="PWD"

# log into the current directory
use_syslog=false
log_dir="PWD"

# relative paths to the warn/failure message templates
errmsg_file="PWD/../../tpl/failmsg.tpl"
warnmsg_file="PWD/../../tpl/warnmsg.tpl"
