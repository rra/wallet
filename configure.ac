dnl Process this file with Autoconf to produce a configure script.
dnl $Id$
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006, 2007, 2008
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.61])
AC_INIT([wallet], [0.8], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AM_INIT_AUTOMAKE([1.10])
AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_RANLIB

AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_CHECK_TYPES([long long])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit])
AC_REPLACE_FUNCS([asprintf strlcat strlcpy])

AC_ARG_WITH([wallet-server],
    [AC_HELP_STRING([--with-wallet-server=HOST], [Default wallet server])],
    [AS_IF([test x"$withval" != xno && test x"$withval" != xyes],
        [AC_DEFINE_UNQUOTED([WALLET_SERVER], ["$withval"],
            [Define to the default server host name.])])])
AC_ARG_WITH([wallet-port],
    [AC_HELP_STRING([--with-wallet-port=PORT],
        [Default wallet server port])],
    [AS_IF([test x"$withval" != xno && test x"$withval" != xyes],
        [AC_DEFINE_UNQUOTED([WALLET_PORT], [$withval],
            [Define to the default server port.])])])

RRA_LIB_REMCTL
RRA_LIB_KRB5
RRA_LIB_AFS
AS_IF([test x"$rra_afs" = xtrue],
    [RRA_LIB_KRB4
     RRA_LIB_AFS_SWITCH
     AC_CHECK_DECLS([ubik_Call], , , [#include <ubik.h>])
     RRA_LIB_AFS_RESTORE])
AM_CONDITIONAL([AFS], [test x"$rra_afs" = xtrue])

AC_ARG_VAR([REMCTLD], [Path to the remctld binary])
AC_PATH_PROG([REMCTLD], [remctld], , [$PATH:/usr/sbin:/usr/local/sbin])
AS_IF([test x"$REMCTLD" != x],
    [AC_DEFINE_UNQUOTED([PATH_REMCTLD], ["$REMCTLD"],
        [Define to the full path to remctld to run remctl tests.])])

dnl Needed to get prototypes for functions like asprintf on Linux.
AC_DEFINE([_GNU_SOURCE], [1], [Define to 1 on Linux to get full prototypes.])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile perl/Makefile.PL tests/data/full.conf])
AC_CONFIG_FILES([tests/client/basic-t], [chmod +x tests/client/basic-t])
AC_CONFIG_FILES([tests/client/full-t], [chmod +x tests/client/full-t])
AC_CONFIG_FILES([tests/client/pod-t], [chmod +x tests/client/pod-t])
AC_CONFIG_FILES([tests/client/prompt-t], [chmod +x tests/client/prompt-t])
AC_CONFIG_FILES([tests/data/cmd-wrapper], [chmod +x tests/data/cmd-wrapper])
AC_CONFIG_FILES([tests/kasetkey/basic-t], [chmod +x tests/kasetkey/basic-t])
AC_CONFIG_FILES([tests/server/admin-t], [chmod +x tests/server/admin-t])
AC_CONFIG_FILES([tests/server/backend-t], [chmod +x tests/server/backend-t])
AC_CONFIG_FILES([tests/server/keytab-t], [chmod +x tests/server/keytab-t])
AC_CONFIG_FILES([tests/server/pod-t], [chmod +x tests/server/pod-t])
AC_CONFIG_FILES([tests/util/xmalloc-t], [chmod +x tests/util/xmalloc-t])
AC_OUTPUT
