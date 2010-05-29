EXTRA_DIST = \
examples/* docs/* man/* tpl/* \
INSTALL.agenda INSTALL.ipaq agenda-config.site

SUBDIRS = src man

install-data-local: log_dir spool_dir uid_bit conf_dir tpl_dir run_dir doc_dir

conf_dir: $(DESTDIR)@with_confdir@

$(DESTDIR)@with_confdir@:
	install -d $(DESTDIR)@with_confdir@

tpl_dir: $(DESTDIR)@datadir@/tpl

$(DESTDIR)@datadir@/tpl: conf_dir
	install -d $(DESTDIR)@datadir@/masqmail/tpl
	install -m 644 tpl/failmsg.tpl $(DESTDIR)@datadir@/masqmail/tpl
	install -m 644 tpl/failmsg.tpl.* $(DESTDIR)@datadir@/masqmail/tpl
	install -m 644 tpl/warnmsg.tpl $(DESTDIR)@datadir@/masqmail/tpl
	install -m 644 tpl/warnmsg.tpl.* $(DESTDIR)@datadir@/masqmail/tpl

doc_dir: conf_dir
	install -d $(DESTDIR)@docdir@
	cp -r docs $(DESTDIR)@docdir@
	cp -r examples $(DESTDIR)@docdir@
	cp ChangeLog NEWS AUTHORS COPYING README TODO $(DESTDIR)@docdir@

log_dir: $(DESTDIR)@with_logdir@

spool_dir: $(DESTDIR)@with_spooldir@

uid_bit: $(DESTDIR)@prefix@/sbin/masqmail
	chmod u+s $(DESTDIR)@prefix@/sbin/masqmail

run_dir:
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)/var/run/masqmail

$(DESTDIR)@with_logdir@:
	[ -d `dirname $(DESTDIR)@with_logdir@` ] || \
		install -d `dirname $(DESTDIR)@with_logdir@`
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_logdir@

$(DESTDIR)@with_spooldir@:
	[ -d `dirname $(DESTDIR)@with_spooldir@` ] || \
		install -d `dirname $(DESTDIR)@with_spooldir@`
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/lock
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/input
	install -d -o @with_user@ -g @with_group@ $(DESTDIR)@with_spooldir@/popuidl

