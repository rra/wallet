dnl Process this file with Autoconf to produce a configure script.
dnl $Id$
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.61])
AC_INIT([wallet], [0.3], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AM_INIT_AUTOMAKE([1.10])
AM_MAINTAINER_MODE

AFS_CPPFLAGS=
AC_ARG_WITH([afs-headers],
    AC_HELP_STRING([--with-afs-headers=DIR],
        [Prefix for AFS headers (for kasetkey)]),
    [if test x"$withval" != xno ; then
        AFS_CPPFLAGS="-I${withval}"
     fi])
AC_SUBST([AFS_CPPFLAGS])
AFS_LDFLAGS=
AC_ARG_WITH([afs-libs],
    AC_HELP_STRING([--with-afs-libs=DIR],
        [Prefix for AFS libraries (for kasetkey)]),
    [if test x"$withval" != xno ; then
        AFS_LDFLAGS="-L${withval} -L${withval}/afs"
     fi])
AC_SUBST([AFS_LDFLAGS])

REMCTL_CPPFLAGS=
REMCTL_LDFLAGS=
AC_ARG_WITH([remctl],
    AC_HELP_STRING([--with-remctl=DIR],
        [Prefix for remctl headers and libraries]),
    [if test x"$withval" != xno ; then
        REMCTL_CPPFLAGS="-I${withval}/include"
        REMCTL_LDFLAGS="-L${withval}/lib"
     fi])
AC_SUBST([REMCTL_CPPFLAGS])
AC_SUBST([REMCTL_LDFLAGS])

AC_ARG_WITH([wallet-server],
    AC_HELP_STRING([--with-wallet-server=HOST], [Default wallet server]),
    [if test x"$withval" != xno ; then
        AC_DEFINE_UNQUOTED([WALLET_SERVER], ["$withval"],
            [Define to the default server host name.])
     fi])
AC_ARG_WITH([wallet-port],
    AC_HELP_STRING([--with-wallet-port=PORT],
        [Default wallet server port]),
    [if test x"$withval" != xno ; then
        AC_DEFINE_UNQUOTED([WALLET_PORT], [$withval],
            [Define to the default server port.])
     fi])

AC_ARG_VAR([REMCTLD], [Path to the remctld binary])
AC_PATH_PROG([REMCTLD], [remctld], , [$PATH:/usr/sbin:/usr/local/sbin])
if test x"$REMCTLD" != x ; then
    AC_DEFINE_UNQUOTED([PATH_REMCTLD], ["$REMCTLD"],
        [Define to the full path to remctld to run remctl tests.])
fi

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket], ,
    [AC_CHECK_LIB([nsl], [socket],
        [LIBS="-lnsl -lsocket $LIBS"], , [-lsocket])])
AC_SEARCH_LIBS([res_search], [resolv], ,
    [AC_SEARCH_LIBS([__res_search], [resolv])])

save_LDFLAGS=$LDFLAGS
LDFLAGS="$AFS_LDFLAGS $LDFLAGS"
AC_CHECK_LIB([afsauthent], [KAM_DeleteUser],
    [AFS_LIBS="-lafsauthent -lafsrpc -lpthread"],
    [AFS_LIBS="-lkauth.krb -lauth.krb -lubik -lrxkad -lrx -llwp -lsys"
     AFS_LIBS="${AFS_LIBS} -lcom_err -lafsutil"],
    [-lafsrpc -lpthread])
LDFLAGS="$save_LDFLAGS"
AC_SUBST([AFS_LIBS])

AC_CHECK_HEADERS([kerberosIV/krb.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
AC_CHECK_DECLS([ubik_Call], , , [#include <ubik.h>])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_CHECK_TYPES([long long])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit])
AC_REPLACE_FUNCS([asprintf])

save_LIBS=$LIBS
LIBS=-lkrb5
AC_CHECK_FUNCS([krb5_get_error_message \
    krb5_free_error_message \
    krb5_get_err_text])
LIBS=$save_LIBS

dnl Needed to get prototypes for functions like asprintf on Linux.
AC_DEFINE([_GNU_SOURCE], [1], [Define to 1 on Linux to get full prototypes.])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile perl/Makefile.PL])
AC_CONFIG_FILES([tests/client/basic-t], [chmod +x tests/client/basic-t])
AC_CONFIG_FILES([tests/server/backend-t], [chmod +x tests/server/backend-t])
AC_CONFIG_FILES([tests/server/keytab-t], [chmod +x tests/server/keytab-t])
AC_CONFIG_FILES([tests/util/xmalloc-t], [chmod +x tests/util/xmalloc-t])
AC_OUTPUT
