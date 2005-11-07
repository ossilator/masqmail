AM_CFLAGS=@CFLAGS@ @GLIB_CFLAGS@ -D_GNU_SOURCE

noinst_LIBRARIES=libbase64.a
noinst_PROGRAMS=base64enc base64dec

base64enc_SOURCES=\
	base64.h\
	base64enc.c\
	base64.c

base64dec_SOURCES=\
	base64.h\
	base64dec.c\
	base64.c

libbase64_a_SOURCES=\
	base64.h\
	base64.c

base64enc_LDADD=@GLIB_LIBS@
base64dec_LDADD=@GLIB_LIBS@
