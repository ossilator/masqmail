EXTRA_DIST=README_MASQMAIL

CFLAGS=@CFLAGS@ -D_GNU_SOURCE -DHAVE_ANSIHEADERS

noinst_LIBRARIES=libident.a

libident_a_SOURCES=\
	ident.h\
	ident.c\
	id_open.c\
	id_close.c\
	id_query.c\
	id_parse.c\
	support.c\
	version.c
