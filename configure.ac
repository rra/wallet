dnl Autoconf configuration for wallet.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006, 2007, 2008, 2010
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

dnl We cannot use -Wall -Werror with AM_INIT_AUTOMAKE since we override
dnl distuninstallcheck (not supported by Perl).
AC_PREREQ([2.64])
AC_INIT([wallet], [0.9], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news silent-rules])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_RANLIB

RRA_LIB_REMCTL
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_FUNCS([krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_kt_free_entry \
    krb5_principal_get_realm])
AC_CHECK_MEMBERS([krb5_keytab_entry.keyblock], , , [#include <krb5.h>])
RRA_LIB_KRB5_RESTORE

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bitypes.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit])
AC_REPLACE_FUNCS([asprintf mkstemp setenv strlcat strlcpy])

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

AC_ARG_VAR([REMCTLD], [Path to the remctld binary])
AC_PATH_PROG([REMCTLD], [remctld], , [$PATH:/usr/sbin:/usr/local/sbin])
AS_IF([test x"$REMCTLD" != x],
    [AC_DEFINE_UNQUOTED([PATH_REMCTLD], ["$REMCTLD"],
        [Define to the full path to remctld to run remctl tests.])])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile perl/Makefile.PL tests/data/full.conf])
AC_CONFIG_FILES([tests/client/basic-t], [chmod +x tests/client/basic-t])
AC_CONFIG_FILES([tests/client/full-t], [chmod +x tests/client/full-t])
AC_CONFIG_FILES([tests/client/prompt-t], [chmod +x tests/client/prompt-t])
AC_OUTPUT
