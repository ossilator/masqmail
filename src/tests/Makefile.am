VPATH = $(srcdir) $(srcdir)/..

AM_CFLAGS = -I$(srcdir)/.. -Wno-pointer-sign @CFLAGS@ @GLIB_CFLAGS@ -D_GNU_SOURCE -DG_DISABLE_DEPRECATED

noinst_PROGRAMS = smtpsend readtest resolvtest

smtpsend_SOURCES = smtpsend.c
nodist_smtpsend_SOURCES = \
	masqmail.h \
	readsock.h \
	smtp_out.h \
	lookup.h \
	accept.c \
	address.c \
	child.c \
	connect.c \
	header.c \
	lookup.c \
	message.c \
	parse.c \
	peopen.c \
	readsock.c \
	smtp_out.c
smtpsend_LDADD = @RESOLV_LIBS@ @GLIB_LIBS@

readtest_SOURCES = readtest.c
nodist_readtest_SOURCES = \
	readsock.c \
	readsock.h
readtest_LDADD = @GLIB_LIBS@

resolvtest_SOURCES = resolvtest.c
nodist_resolvtest_SOURCES = \
	lookup.c
resolvtest_LDADD = @RESOLV_LIBS@ @GLIB_LIBS@
