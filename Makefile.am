EXTRA_DIST = examples docs man tpl misc

SUBDIRS = src man

install-data-local: log_dir spool_dir uid_bit conf_dir tpl_dir run_dir doc_dir rmail

uninstall-local: rm-rmail rm-doc_dir rm-tpl_dir rm-conf_dir rm-run_dir rm-spool_dir rm-log_dir


conf_dir: $(DESTDIR)@with_confdir@

$(DESTDIR)@with_confdir@:
	install -d $(DESTDIR)@with_confdir@

rm-conf_dir:
	rmdir $(DESTDIR)@with_confdir@  # removes only if empty


tpl_dir: $(DESTDIR)@datadir@/tpl

$(DESTDIR)@datadir@/tpl: conf_dir
	install -d $(DESTDIR)@datadir@/masqmail/tpl
	cp tpl/* $(DESTDIR)@datadir@/masqmail/tpl
	chmod 644 $(DESTDIR)@datadir@/masqmail/tpl/*


doc_dir:
	install -d $(DESTDIR)@docdir@
	cp -r docs $(DESTDIR)@docdir@
	cp -r examples $(DESTDIR)@docdir@
	cp ChangeLog NEWS AUTHORS COPYING README TODO $(DESTDIR)@docdir@


uid_bit: $(DESTDIR)@prefix@/sbin/masqmail
	chmod u+s $(DESTDIR)@prefix@/sbin/masqmail


run_dir:
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)/var/run/masqmail

rm-run_dir:
	rm -rf $(DESTDIR)/var/run/masqmail


log_dir: $(DESTDIR)@with_logdir@

$(DESTDIR)@with_logdir@:
	[ -d `dirname $(DESTDIR)@with_logdir@` ] || \
		install -d `dirname $(DESTDIR)@with_logdir@`
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_logdir@

rm-log_dir:
	rmdir $(DESTDIR)@with_logdir@  # removes only if empty


spool_dir: $(DESTDIR)@with_spooldir@

$(DESTDIR)@with_spooldir@:
	[ -d `dirname $(DESTDIR)@with_spooldir@` ] || \
		install -d `dirname $(DESTDIR)@with_spooldir@`
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/lock
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/input
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/popuidl

rm-spool_dir:
	: # removal fails if the dirs are non-empty
	: # this prevents losing spooled files
	rmdir $(DESTDIR)@with_spooldir@/lock
	rmdir $(DESTDIR)@with_spooldir@/input
	rmdir $(DESTDIR)@with_spooldir@/popuidl
	rmdir $(DESTDIR)@with_spooldir@

rmail:
	[ -d "$(DESTDIR)@prefix@/bin" ] || mkdir -p "$(DESTDIR)@prefix@/bin"
	sed '/^SENDMAIL/s,/usr/sbin/sendmail,$(DESTDIR)@prefix@/sbin/masqmail,'\
	    contrib/rmail >$(DESTDIR)@prefix@/bin/rmail
	chmod 755 $(DESTDIR)@prefix@/bin/rmail

rm-rmail:
	rm -f $(DESTDIR)@prefix@/bin/rmail

rm-doc_dir:
	cd $(DESTDIR)@docdir@ ;\
	rm -rf docs examples ;\
	rm -f ChangeLog NEWS AUTHORS COPYING README TODO
	rmdir $(DESTDIR)@docdir@

rm-tpl_dir:
	cd $(DESTDIR)@datadir@ ;\
	rm -rf masqmail
