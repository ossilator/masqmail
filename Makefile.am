EXTRA_DIST = examples/* docs/*.html THOUGHTS
SUBDIRS = src tests

install-data-local: log_dir spool_dir uid_bit

log_dir: $(DESTDIR)@with_logdir@

spool_dir: $(DESTDIR)@with_spooldir@

uid_bit: $(DESTDIR)@prefix@/sbin/masqmail
	chmod u+s $(DESTDIR)@prefix@/sbin/masqmail

$(DESTDIR)@with_logdir@:
	mkdir $(DESTDIR)@with_logdir@
	chown @with_user@.@with_group@ $(DESTDIR)@with_logdir@

$(DESTDIR)@with_spooldir@:
	mkdir $(DESTDIR)@with_spooldir@
	mkdir $(DESTDIR)@with_spooldir@/input
	chown -R @with_user@.@with_group@ $(DESTDIR)@with_spooldir@
