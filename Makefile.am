EXTRA_DIST = examples/example.get examples/example.route examples/masqmail.conf docs/README docs/install.html docs/man/masqmail*.[0-9] docs/xml/*.xml THOUGHTS suse/masqmail suse/masqmail.spec suse/masqmail.spec.in redhat/masqmail redhat/masqmail.spec redhat/masqmail.spec.in

SUBDIRS = src tests docs

install-data-local: log_dir spool_dir uid_bit

log_dir: $(DESTDIR)@with_logdir@

spool_dir: $(DESTDIR)@with_spooldir@

uid_bit: $(DESTDIR)@prefix@/sbin/masqmail
	chmod u+s $(DESTDIR)@prefix@/sbin/masqmail

$(DESTDIR)@with_logdir@:
	mkdir -p $(DESTDIR)@with_logdir@
	chown @with_user@.@with_group@ $(DESTDIR)@with_logdir@

$(DESTDIR)@with_spooldir@:
	mkdir -p $(DESTDIR)@with_spooldir@
	mkdir -p $(DESTDIR)@with_spooldir@/input
	mkdir -p $(DESTDIR)@with_spooldir@/popuidl
	chown -R @with_user@.@with_group@ $(DESTDIR)@with_spooldir@

