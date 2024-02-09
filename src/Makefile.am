SUBDIRS = tests

AM_CFLAGS=-Wno-pointer-sign @CFLAGS@ @GLIB_CFLAGS@ -D_GNU_SOURCE -DG_DISABLE_DEPRECATED

sbin_PROGRAMS=masqmail
bin_PROGRAMS=mservdetect
check_PROGRAMS=tst_parse

TESTS = $(check_PROGRAMS)

install-exec-hook:
	chmod u+s $(DESTDIR)@sbindir@/masqmail
	cd $(DESTDIR)@sbindir@ && \
		$(LN_S) -f masqmail sendmail && \
		$(LN_S) -f masqmail mailq && \
		$(LN_S) -f masqmail mailrm && \
		$(LN_S) -f masqmail runq && \
		$(LN_S) -f masqmail in.smtpd

uninstall-hook:
	-rm -f $(DESTDIR)@sbindir@/sendmail \
		$(DESTDIR)@sbindir@/mailq \
		$(DESTDIR)@sbindir@/mailrm \
		$(DESTDIR)@sbindir@/runq \
		$(DESTDIR)@sbindir@/in.smtpd

masqmail_SOURCES=\
	dotlock.h\
	masqmail.h\
	readsock.h\
	smtp_out.h\
	lookup.h\
	accept.c\
	address.c\
	alias.c\
	child.c\
	connect.c\
	conf.c\
	deliver.c\
	dotlock.c\
	expand.c\
	fail_msg.c\
	header.c\
	interface.c\
	local.c\
	log.c\
	listen.c\
	lookup.c\
	masqmail.c\
	message.c\
	online.c\
	parse.c\
	peopen.c\
	peopen.h\
	permissions.c\
	readsock.c\
	rewrite.c\
	route.c\
	queue.c\
	smtp_in.c\
	smtp_out.c\
	spool.c\
	tables.c\
	timeival.c\
	whereami.h\
	whereami.c

mservdetect_SOURCES=\
	masqmail.h\
	readsock.h\
	mservdetect.c\
	readsock.c

tst_parse_SOURCES=\
	tst_parse.c
tst_parse_LDADD=@GLIB_LIBS@

masqmail_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@ @LOCKFILE_LIBS@
mservdetect_LDADD=@GLIB_LIBS@
