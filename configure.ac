dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT(
	[MasqMail], m4_esyscmd_s([$(dirname "$0")/version.sh]),
	[https://github.com/ossilator/masqmail/issues],
	[masqmail], [https://github.com/ossilator/masqmail])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/masqmail.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE()

dnl Checks for programs.

AC_PROG_CC

AC_PROG_LN_S

dnl Checks for libraries.

PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)

dnl resolver support (default is use it)
AC_ARG_ENABLE(resolver,
	[  --disable-resolver      disable resolver support],
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
			AC_LINK_IFELSE(
				[AC_LANG_PROGRAM(
					[[#include <resolv.h>]],
					[[res_search (0, 0, 0, 0, 0);]]
				)],
				[RESOLV_LIBS="-lresolv"; has_resolv=yes; AC_MSG_RESULT(yes)],
				[AC_MSG_RESULT(no)])
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
AC_CHECK_HEADERS(fcntl.h sys/time.h syslog.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_FNMATCH
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(select socket strerror strstr)

dnl user and group configuration
AC_ARG_WITH(user,
	[  --with-user=USER        set user [mail]],
	)
if test "x$with_user" = 'x'; then
	with_user='mail'
fi

AC_ARG_WITH(group,
	[  --with-group=GROUP      set group [mail]],
	)
if test "x$with_group" = 'x'; then
	with_group='mail'
fi

dnl debugging support (default is use it)
AC_ARG_ENABLE(debug,
	[  --disable-debug         disable debugging],
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

dnl optional features

dnl auth support (default: use it)
AC_ARG_ENABLE(auth,
	[  --disable-auth          disable AUTH (RFC 2554) client support],
	if test "x$enable_auth" != 'xno'; then
		auth_enabled='yes'
	fi,
	auth_enabled='yes'
	)
if test "x$auth_enabled" = xyes; then
	AC_DEFINE(ENABLE_AUTH, 1, [If AUTH is enabled])
fi

dnl liblockfile
AC_ARG_WITH(liblockfile,
	[  --with-liblockfile      use liblock (for Debian)],
	)
if test "x$with_liblockfile" = 'xno'; then
	with_liblockfile=''
fi
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
	[  --with-logdir=DIR       set log directory [/var/log/masqmail]],
	,
        with_logdir='/var/log/masqmail'
	)
AC_DEFINE_UNQUOTED(LOG_DIR, "${with_logdir}", [The log directory])
AC_SUBST(with_logdir)

AC_ARG_WITH(spooldir,
	[  --with-spooldir=DIR     set spool directory [/var/spool/masqmail]],
	,
	with_spooldir='/var/spool/masqmail'
	)
AC_DEFINE_UNQUOTED(SPOOL_DIR, "${with_spooldir}", [The spool directory])
AC_SUBST(with_spooldir)

dnl configuration file
AC_ARG_WITH(confdir,
	[  --with-confdir=DIR      directory for configuration [/etc/masqmail]],
	,
	with_confdir='/etc/masqmail'
	)
AC_DEFINE_UNQUOTED(CONF_DIR, "${with_confdir}", [The configuration file location])
AC_SUBST(with_confdir)

dnl dir for pid files
AC_ARG_WITH(piddir,
	[  --with-piddir=DIR       directory for pid files [/var/run]],
	,
	with_piddir='/var/run'
	)
AC_DEFINE_UNQUOTED(PID_DIR, "${with_piddir}", [The pid file location])
AC_SUBST(with_piddir)

dnl dir for lock files
AC_ARG_WITH(lockdir,
	[  --with-lockdir=DIR      directory for lock files [/var/lock/masqmail]],
	,
	with_lockdir='/var/lock/masqmail'
	)
AC_DEFINE_UNQUOTED(LOCK_DIR, "${with_lockdir}", [The lock file location])
AC_SUBST(with_lockdir)

AX_RECURSIVE_EVAL([${datadir}/masqmail], [xmmdatadir])
AC_SUBST(xmmdatadir)
AC_DEFINE_UNQUOTED(DATA_DIR, "$xmmdatadir", [The data directory])

AX_RECURSIVE_EVAL([${bindir}], [xbindir])
AC_SUBST(xbindir)

AX_RECURSIVE_EVAL([${sbindir}], [xsbindir])
AC_DEFINE_UNQUOTED(SBINDIR, "$xsbindir", [The sbin directory])
AC_SUBST(xsbindir)

RELEASE_DATE=`date -r "$0" +%F`
AC_SUBST(RELEASE_DATE)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/tests/Makefile
	man/Makefile
	man/masqmail.8
	man/mservdetect.1
	man/masqmail.aliases.5
	man/masqmail.conf.5
	man/masqmail.route.5
	man/rmail.8
	docs/Makefile
	examples/Makefile
	tpl/Makefile
])
AC_OUTPUT
