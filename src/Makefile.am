SUBDIRS=base64 md5 libident

AM_CFLAGS=@CFLAGS@ @GLIB_CFLAGS@ -D_GNU_SOURCE -DG_DISABLE_DEPRECATED

sbin_PROGRAMS=masqmail
bin_PROGRAMS=mservdetect
noinst_PROGRAMS=smtpsend readtest

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
	timeival.c

smtpsend_SOURCES=\
	smtpsend.c\
	masqmail.h\
	readsock.h\
	smtp_out.h\
	lookup.h\
	accept.c\
	address.c\
	child.c\
	connect.c\
	header.c\
	interface.c\
	lookup.c\
	message.c\
	parse.c\
	peopen.c\
	readsock.c\
	smtp_out.c

mservdetect_SOURCES=\
	masqmail.h\
	readsock.h\
	mservdetect.c\
	readsock.c\
	peopen.c

readtest_SOURCES=\
	readsock.c\
	readsock.h\
	readtest.c

masqmail_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@ @LOCKFILE_LIBS@ @MD5_LIBS@ @BASE64_LIBS@ @IDENT_LIBS@
smtpsend_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@ @MD5_LIBS@ @BASE64_LIBS@
mservdetect_LDADD=@GLIB_LIBS@
readtest_LDADD=@GLIB_LIBS@
