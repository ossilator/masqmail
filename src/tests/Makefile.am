VPATH = ..

AM_CFLAGS = -I.. -Wno-pointer-sign @CFLAGS@ @GLIB_CFLAGS@ -D_GNU_SOURCE -DG_DISABLE_DEPRECATED

noinst_PROGRAMS = smtpsend readtest resolvtest

smtpsend_SOURCES = \
	smtpsend.c \
	masqmail.h \
	readsock.h \
	smtp_out.h \
	lookup.h \
	accept.c \
	address.c \
	connect.c \
	header.c \
	lookup.c \
	message.c \
	parse.c \
	readsock.c \
	smtp_out.c
smtpsend_LDADD = @RESOLV_LIBS@ @GLIB_LIBS@

readtest_SOURCES = \
	readsock.c \
	readsock.h \
	readtest.c
readtest_LDADD = @GLIB_LIBS@

resolvtest_SOURCES = \
	resolvtest.c \
	lookup.c
resolvtest_LDADD = @RESOLV_LIBS@ @GLIB_LIBS@
