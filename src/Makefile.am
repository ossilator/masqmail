CFLAGS=@GLIB_CFLAGS@ -D_GNU_SOURCE

sbin_PROGRAMS=masqmail
#noinst_PROGRAMS=adr_test rewr_test minimasq
noinst_PROGRAMS=minimasq aliastest

aliastest_SOURCES=\
	masqmail.h\
	aliastest.c\
	accept.c\
	alias.c\
	message.c\
	parse.c\
	tables.c	

minimasq_SOURCES=\
	masqmail.h\
	smtp_out.h\
	lookup.h\
	minimasq.c\
	accept.c\
	connect.c\
	lookup.c\
	message.c\
	parse.c\
	smtp_out.c

masqmail_SOURCES=\
	masqmail.h\
	smtp_out.h\
	lookup.h\
	accept.c\
	alias.c\
	connect.c\
	conf.c\
	deliver.c\
	local.c\
	log.c\
	listen.c\
	lookup.c\
	masqmail.c\
	message.c\
	mserver.c\
	online.c\
	parse.c\
	rewrite.c\
	route.c\
	queue.c\
	smtp_in.c\
	smtp_out.c\
	spool.c\
	tables.c

minimasq_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@
masqmail_LDADD=@RESOLV_LIBS@ @GLIB_LIBS@ @LOCKFILE_LIBS@
aliastest_LDADD=@GLIB_LIBS@
