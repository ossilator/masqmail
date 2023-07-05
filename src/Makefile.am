SUBDIRS=base64 md5 libident

CFLAGS=@CFLAGS@ @GLIB_CFLAGS@ -D_GNU_SOURCE

sbin_PROGRAMS=masqmail
noinst_PROGRAMS=smtpsend expandtest readtest

masqmail_SOURCES=\
	masqmail.h\
	readsock.h\
	smtp_out.h\
	lookup.h\
	accept.c\
	alias.c\
	child.c\
	connect.c\
	conf.c\
	deliver.c\
	expand.c\
	get.c\
	header.c\
	interface.c\
	local.c\
	log.c\
	listen.c\
	lookup.c\
	masqmail.c\
	message.c\
	mserver.c\
	online.c\
	parse.c\
	peopen.c\
	peopen.h\
	permissions.c\
	pop3_in.c\
	pop3_in.h\
	readsock.c\
	rewrite.c\
	route.c\
	queue.c\
	smtp_in.c\
	smtp_out.c\
	spool.c\
	tables.c

smtpsend_SOURCES=\
	smtpsend.c\
	masqmail.h\
	readsock.h\
	smtp_out.h\
	lookup.h\
	accept.c\
	child.c\
	connect.c\
	header.c\
	interface.c\
	lookup.c\
	message.c\
	parse.c\
	readsock.c\
	smtp_out.c

expandtest_SOURCES=\
	expandtest.c\
	expand.c\
	tables.c

readtest_SOURCES=\
	readsock.c\
	readsock.h\
	readtest.c

masqmail_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@ @LOCKFILE_LIBS@ @MD5_LIBS@ @BASE64_LIBS@ @IDENT_LIBS@
smtpsend_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@ @MD5_LIBS@ @BASE64_LIBS@
expandtest_LDADD=@GLIB_LIBS@
readtest_LDADD=@GLIB_LIBS@
