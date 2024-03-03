EXTRA_DIST = admin devel LICENSES

SUBDIRS = src man docs examples tpl tests

doc_DATA = ChangeLog NEWS AUTHORS COPYING README TODO INSTALL THANKS

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-confdir=\$${prefix}/etc/masqmail \
	--with-logdir=\$${prefix}/var/log/masqmail \
	--with-spooldir=\$${prefix}/var/spool/masqmail

install-data-local: rmail conf_dir

uninstall-local: rm-rmail rm-dirs

conf_dir:
	install -d $(DESTDIR)@with_confdir@

rm-dirs:
	: # removes only if empty
	-rmdir $(DESTDIR)@with_confdir@
	-rmdir $(DESTDIR)@with_logdir@
	-rmdir $(DESTDIR)@with_spooldir@

rmail:
	[ -d "$(DESTDIR)@sbindir@" ] || mkdir -p "$(DESTDIR)@sbindir@"
	sed '/^SENDMAIL/s,/usr/sbin/sendmail,@sbindir@/masqmail,'\
	    @srcdir@/admin/rmail >$(DESTDIR)@sbindir@/rmail
	chmod 755 $(DESTDIR)@sbindir@/rmail

rm-rmail:
	rm -f $(DESTDIR)@sbindir@/rmail

dist-sign: distcheck
	gpg -b -a $(PACKAGE)-$(VERSION).tar.gz
