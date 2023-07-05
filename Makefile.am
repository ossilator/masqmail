EXTRA_DIST = examples docs tpl devel

SUBDIRS = src man

install-data-local: tpl_dir doc_dir rmail conf_dir

uninstall-local: rm-rmail rm-doc_dir rm-tpl_dir rm-dirs

conf_dir:
	install -d $(DESTDIR)@with_confdir@

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

rm-dirs:
	: # removes only if empty
	rmdir $(DESTDIR)@with_confdir@
	rmdir $(DESTDIR)@with_logdir@
	rmdir $(DESTDIR)@with_spooldir@

rmail:
	[ -d "$(DESTDIR)@prefix@/sbin" ] || mkdir -p "$(DESTDIR)@prefix@/sbin"
	sed '/^SENDMAIL/s,/usr/sbin/sendmail,$(DESTDIR)@prefix@/sbin/masqmail,'\
	    admin/rmail >$(DESTDIR)@prefix@/sbin/rmail
	chmod 755 $(DESTDIR)@prefix@/sbin/rmail

rm-rmail:
	rm -f $(DESTDIR)@prefix@/sbin/rmail
