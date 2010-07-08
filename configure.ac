dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(masqmail, 0.3.0, meillo@marmaro.de)
AC_CONFIG_SRCDIR([src/masqmail.c])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE()

dnl Checks for programs.

dnl Checks for libraries.

AC_PROG_CC
AC_ISC_POSIX
AC_STDC_HEADERS
dnl AC_ARG_PROGRAM
AC_PROG_RANLIB

PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)

dnl resolver support (default is use it)
AC_ARG_ENABLE(resolver,
	[  --disable-resolver       disable resolver support],
	if test "$enable_resolver" != 'no'; then
		resolver_enabled='yes'
	fi,
	resolver_enabled='yes'
	)

if test "$resolver_enabled" = yes; then
	AC_DEFINE(ENABLE_RESOLVER, 1, [If the resolver is to be used])
dnl checks necessary for libc5:
dnl if there is res_search in libc, it is probably libc5
dnl if not, it is probably libc6 and we need libresolv
	AC_CHECK_LIB(c, res_search, need_resolv=no, need_resolv=yes)
	if test "$need_resolv" = yes; then
		AC_CHECK_LIB(resolv, res_search,
			has_resolv=yes; RESOLV_LIBS="-lresolv",
			has_resolv=no)
		if test "$has_resolv" = no; then
			saved_LIBS="$LIBS"
			LIBS="$LIBS -lresolv"
			AC_MSG_CHECKING(for res_search in -lresolv)
			AC_TRY_LINK([#include <resolv.h>],
				[res_search (0, 0, 0, 0, 0);],
				RESOLV_LIBS="-lresolv"; has_resolv=yes; AC_MSG_RESULT(yes),
				AC_MSG_RESULT(no));
			LIBS="$saved_LIBS"
		fi
		if test "$has_resolv" = no; then
			AC_MSG_ERROR("no libresolv")
			RESOLV_LIBS=''
		fi
	fi
else
	RESOLV_LIBS=''
fi
AC_SUBST(RESOLV_LIBS)

dnl if there is no getline, we define it using getdelim in src/masqmail.h
AC_CHECK_FUNCS(getline)

dnl if there is no fdatasync, we define it to fsync in src/masqmail.h
AC_CHECK_FUNCS(fdatasync)

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h sys/time.h syslog.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_FNMATCH
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(select socket strerror strstr)

dnl user and group configuration
AC_ARG_WITH(user,
	[  --with-user=USER         set user [mail]],
	)
if test "x$with_user" = 'x'; then
	with_user='mail'
fi

AC_ARG_WITH(group,
	[  --with-group=GROUP       set group [trusted]],
	)
if test "x$with_group" = 'x'; then
	with_group='trusted'
fi

dnl debugging support (default is use it)
AC_ARG_ENABLE(debug,
	[  --disable-debug          disable debugging],
	if test "x$enable_debug" != 'xno'; then
		debug_enabled='yes'
	fi,
	debug_enabled='yes'
	)
if test "x$debug_enabled" = xyes; then
	AC_DEFINE(ENABLE_DEBUG, 1, [If debugging is enabled])
fi

AC_DEFINE_UNQUOTED(DEF_MAIL_USER, "${with_user}", [The mail user])
AC_SUBST(with_user)
AC_DEFINE_UNQUOTED(DEF_MAIL_GROUP, "${with_group}", [The mail group])
AC_SUBST(with_group)

dnl link glib statically?
AC_ARG_WITH(glib_static,
	[  --with-glib-static=path  link glib statically (path mandatory!)],
	)
if test "x$with_glib_static" != 'x'; then
	GLIB_LIBS=$with_glib_static
	AC_SUBST(GLIB_LIBS)
fi

dnl optional features
MD5_LIBS=''
BASE64_LIBS=''

dnl smtp server support (default is use it)
AC_ARG_ENABLE(smtp_server,
	[  --disable-smtp-server    disable smtp server support],
	if test "x$enable_smtp_server" != 'xno'; then
		smtp_server_enabled='yes'
	fi,
	smtp_server_enabled='yes'
	)
if test "x$smtp_server_enabled" = xyes; then
	AC_DEFINE(ENABLE_SMTP_SERVER, 1, [If the SMTP server is enabled])
fi

dnl pop support (default is use it)
AC_ARG_ENABLE(pop3,
	[  --disable-pop3           disable pop3 support],
	if test "x$enable_pop3" != 'xno'; then
		pop3_enabled='yes'
	fi,
	)
if test "x$pop3_enabled" = xyes; then
	AC_DEFINE(ENABLE_POP3, 1, [If the POP3 support is enabled])
#	MD5_LIBS='md5/libmd5c.a'
	need_md5='yes'
fi

dnl auth support (default is to not use it)
AC_ARG_ENABLE(auth,
	[  --enable-auth            enable AUTH (RFC 2554) client support],
	if test "x$enable_auth" != 'xno'; then
		auth_enabled='yes'
	fi,
	)
if test "x$auth_enabled" = xyes; then
	AC_DEFINE(ENABLE_AUTH, 1, [If AUTH is enabled])
	BASE64_LIBS='base64/libbase64.a'
#	MD5_LIBS='md5/libmd5c.a'
	need_md5='yes'
fi
AC_SUBST(BASE64_LIBS)

dnl maildir support (default is to not use it)
AC_ARG_ENABLE(maildir,
	[  --enable-maildir            enable qmail style maildir support],
	if test "x$enable_maildir" != 'xno'; then
		maildir_enabled='yes'
	fi,
	)
if test "x$maildir_enabled" = xyes; then
	AC_DEFINE(ENABLE_MAILDIR, 1, [If Maildirs are enabled])
fi

dnl libcrypto
AC_ARG_WITH(libcrypto,
	[  --with-libcrypto         use libcrypto],
	)
if test "x$with_libcrypto" != 'xyes'; then
	with_libcrypto='no'
fi

if test "x$need_md5" = 'xyes'; then
dnl check whether we have md5 in libcrypto if md5 needed and we shall link with libcrypto
	if test "x$with_libcrypto" = "xyes"; then
		AC_CHECK_LIB(crypto, MD5, has_crypto='yes', AC_MSG_ERROR('no libcrypto'))
		if test "x$has_crypto" = 'xyes'; then
			AC_DEFINE(USE_LIB_CRYPTO, 1, [If libcrypto is available])
			MD5_LIBS='-lcrypto'
		fi
	else
		MD5_LIBS='md5/libmd5c.a'
	fi
fi
AC_SUBST(MD5_LIBS)

dnl ident support (default is to not use it)
IDENT_LIBS=''
AC_ARG_ENABLE(ident,
	[  --enable-ident           enable ident (RFC 1413) support],
	if test "x$enable_ident" != 'xno'; then
		ident_enabled='yes'
	fi,
	)
AC_SUBST(has_ident)
if test "x$ident_enabled" = xyes; then
	AC_DEFINE(ENABLE_IDENT, 1, [If ident is enabled])
	AC_CHECK_LIB(ident, ident_id, IDENT_LIBS='-lident', IDENT_LIBS='libident/libident.a')
fi
AC_SUBST(IDENT_LIBS)

dnl liblockfile
AC_ARG_WITH(liblockfile,
	[  --with-liblockfile       use liblock (for Debian)],
	)
if test "x$with_liblockfile" != 'x'; then
	with_liblockfile='yes'
fi
if test "x$with_liblockfile" = xyes; then
	AC_CHECK_LIB(lockfile, maillock, has_lockfile=yes, AC_MSG_ERROR("no liblockfile"))
	LOCKFILE_LIBS='-llockfile'
	AC_DEFINE(USE_LIBLOCKFILE, 1, [If liblockfile is to be used])
else
	LOCKFILE_LIBS=''
fi
AC_SUBST(LOCKFILE_LIBS)
AC_SUBST(USE_LIBLOCKFILE)

dnl log and spool directories
AC_ARG_WITH(logdir,
	[  --with-logdir=DIR        set log directory [/var/log/masqmail]],
	,
        with_logdir='/var/log/masqmail/'
	)
AC_DEFINE_UNQUOTED(LOG_DIR, "${with_logdir}", [The log directory])
AC_SUBST(with_logdir)

AC_ARG_WITH(spooldir,
	[  --with-spooldir=DIR      set spool directory [/var/spool/masqmail]],
	,
	with_spooldir='/var/spool/masqmail/'
	)
AC_DEFINE_UNQUOTED(SPOOL_DIR, "${with_spooldir}", [The spool directory])
AC_SUBST(with_spooldir)

dnl configuration file
AC_ARG_WITH(confdir,
	[  --with-confdir           directory for configuration [/etc/masqmail]],
	,
	with_confdir='/etc/masqmail'
	)
AC_DEFINE_UNQUOTED(CONF_DIR, "${with_confdir}", [The configuration file location])
AC_SUBST(with_confdir)

test "x$prefix" = xNONE && prefix="$ac_default_prefix"

dnl well, /me/ thought that autoconf should make things _easy_ ... -- oku
dnl I needed the two `eval's to get the variable expanded in all cases -- meillo
dnl this is just horrible! -- meillo
AC_DEFINE_UNQUOTED(DATA_DIR, "`eval eval echo $datadir`/masqmail", [The data directory])

dnl gymnastics to get the correct path where masqmail should be installed
dnl we need this to call ourselves in failmsg.c
if test "x${exec_prefix}" != 'xNONE'; then
	AC_DEFINE_UNQUOTED(SBINDIR, "${exec_prefix}/sbin", [The sbin directory])
else
	if test "x${prefix}" != 'xNONE'; then
		AC_DEFINE_UNQUOTED(SBINDIR, "${prefix}/sbin")
	else
		AC_DEFINE_UNQUOTED(SBINDIR, "/usr/sbin")
	fi
fi

AC_OUTPUT(Makefile \
	src/Makefile \
	src/base64/Makefile \
	src/md5/Makefile \
	src/libident/Makefile \
	man/Makefile
	)
