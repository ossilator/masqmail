EXTRA_DIST = \
examples/example.get examples/example.route examples/masqmail.conf \
docs/README docs/man/m*.[0-9] \
suse/masqmail suse/masqmail.spec suse/masqmail.spec.in \
redhat/masqmail redhat/masqmail.spec redhat/masqmail.spec.in \
tpl/failmsg.tpl tpl/failmsg.tpl.de tpl/failmsg.tpl.fr tpl/failmsg.tpl.it \
INSTALL.agenda agenda-config.site

SUBDIRS = src tests docs debian

install-data-local: log_dir spool_dir uid_bit conf_dir tpl_dir

conf_dir: $(DESTDIR)@with_confdir@

$(DESTDIR)@with_confdir@:
	mkdir -p $(DESTDIR)@with_confdir@

tpl_dir: $(DESTDIR)@with_confdir@/tpl

$(DESTDIR)@with_confdir@/tpl: conf_dir
	mkdir -p $(DESTDIR)@with_confdir@/tpl
	cp tpl/failmsg.tpl $(DESTDIR)@with_confdir@/tpl
	cp tpl/failmsg.tpl.{de,fr,it} $(DESTDIR)@with_confdir@/tpl
	chown @with_user@.@with_group@ $(DESTDIR)@with_confdir@/tpl
	chown @with_user@.@with_group@ $(DESTDIR)@with_confdir@/tpl/failmsg.tpl
	chown @with_user@.@with_group@ $(DESTDIR)@with_confdir@/tpl/failmsg.tpl.{de,fr,it}

log_dir: $(DESTDIR)@with_logdir@

spool_dir: $(DESTDIR)@with_spooldir@

uid_bit: $(DESTDIR)@prefix@/sbin/masqmail
	chmod u+s $(DESTDIR)@prefix@/sbin/masqmail

$(DESTDIR)@with_logdir@:
	mkdir -p $(DESTDIR)@with_logdir@
	chown @with_user@.@with_group@ $(DESTDIR)@with_logdir@

$(DESTDIR)@with_spooldir@:
	mkdir -p $(DESTDIR)@with_spooldir@
	mkdir -p $(DESTDIR)@with_spooldir@/lock
	mkdir -p $(DESTDIR)@with_spooldir@/input
	mkdir -p $(DESTDIR)@with_spooldir@/popuidl
	chown -R @with_user@.@with_group@ $(DESTDIR)@with_spooldir@

