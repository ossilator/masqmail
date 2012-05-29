EXTRA_DIST = examples docs man tpl devel

SUBDIRS = src man

install-data-local: log_dir spool_dir uid_bit conf_dir tpl_dir pid_dir doc_dir rmail

uninstall-local: rm-rmail rm-doc_dir rm-tpl_dir rm-conf_dir rm-pid_dir rm-spool_dir rm-log_dir


conf_dir:
	install -d $(DESTDIR)@with_confdir@

rm-conf_dir:
	rmdir $(DESTDIR)@with_confdir@  # removes only if empty


tpl_dir:
	install -d $(DESTDIR)@datadir@/masqmail/tpl
	cp tpl/* $(DESTDIR)@datadir@/masqmail/tpl
	chmod 644 $(DESTDIR)@datadir@/masqmail/tpl/*

rm-tpl_dir:
	rm -rf $(DESTDIR)@datadir@/masqmail/


doc_dir:
	install -d $(DESTDIR)@docdir@
	cp -r docs $(DESTDIR)@docdir@
	cp -r examples $(DESTDIR)@docdir@
	cp ChangeLog NEWS AUTHORS COPYING README TODO INSTALL THANKS $(DESTDIR)@docdir@

rm-doc_dir:
	cd $(DESTDIR)@docdir@ && ( \
	    rm -rf docs examples ; \
	    rm -f ChangeLog NEWS AUTHORS COPYING README TODO INSTALL THANKS ; \
	)
	rmdir $(DESTDIR)@docdir@


pid_dir:
	install -d $(DESTDIR)@with_piddir@

rm-pid_dir:
	rm -rf $(DESTDIR)@with_piddir@


log_dir:
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_logdir@

rm-log_dir:
	rmdir $(DESTDIR)@with_logdir@  # removes only if empty


spool_dir:
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/lock
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/input

rm-spool_dir:
	: # removal fails if the dirs are non-empty
	: # this prevents losing spooled files
	rmdir $(DESTDIR)@with_spooldir@/lock
	rmdir $(DESTDIR)@with_spooldir@/input
	rmdir $(DESTDIR)@with_spooldir@

rmail:
	[ -d "$(DESTDIR)@prefix@/sbin" ] || mkdir -p "$(DESTDIR)@prefix@/sbin"
	sed '/^SENDMAIL/s,/usr/sbin/sendmail,$(DESTDIR)@prefix@/sbin/masqmail,'\
	    admin/rmail >$(DESTDIR)@prefix@/sbin/rmail
	chmod 755 $(DESTDIR)@prefix@/sbin/rmail

rm-rmail:
	rm -f $(DESTDIR)@prefix@/sbin/rmail


uid_bit:
	chmod u+s $(DESTDIR)@prefix@/sbin/masqmail
