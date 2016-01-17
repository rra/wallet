dnl Autoconf configuration for wallet.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2006, 2007, 2008, 2010, 2013, 2014
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([wallet], [1.2], [eagle@eyrie.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news dist-xz foreign silent-rules subdir-objects
    -Wall -Wno-override -Werror])
AM_MAINTAINER_MODE

dnl Detect unexpanded macros.
m4_pattern_forbid([^_?RRA_])

dnl AM_PROG_AR is required for Automake 1.12 by Libtool but not defined at all
dnl (or needed) in Automake 1.11.  Work around this bug.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
RRA_PROG_CC_CLANG
AC_SYS_LARGEFILE
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_MKDIR_P

dnl Allow modification of the default wallet port, and setting a default
dnl wallet server when none is defined in krb5.conf.
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

dnl Probe for required libraries.
RRA_LIB_REMCTL
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_FUNCS([krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_principal_get_realm])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])
AC_CHECK_DECLS([krb5_kt_free_entry], [], [], [RRA_INCLUDES_KRB5])
AC_CHECK_DECLS([krb5_kt_free_entry])
AC_CHECK_MEMBERS([krb5_keytab_entry.keyblock], [], [], [RRA_INCLUDES_KRB5])
RRA_LIB_KRB5_RESTORE

dnl Probe for properties of the C library.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bitypes.h sys/uio.h sys/time.h syslog.h])
AC_CHECK_DECLS([snprintf, strlcat, strlcpy, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit])
AC_REPLACE_FUNCS([asprintf mkstemp reallocarray setenv strlcat strlcpy])

dnl Find a remctld binary for the test suite.
AC_ARG_VAR([REMCTLD], [Path to the remctld binary])
AC_PATH_PROG([REMCTLD], [remctld], [], [$PATH:/usr/sbin:/usr/local/sbin])
AS_IF([test x"$REMCTLD" != x],
    [AC_DEFINE_UNQUOTED([PATH_REMCTLD], ["$REMCTLD"],
        [Define to the full path to remctld to run remctl tests.])])

dnl Output section.
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([tests/client/basic-t], [chmod +x tests/client/basic-t])
AC_CONFIG_FILES([tests/client/full-t], [chmod +x tests/client/full-t])
AC_CONFIG_FILES([tests/client/prompt-t], [chmod +x tests/client/prompt-t])
AC_CONFIG_FILES([tests/client/rekey-t], [chmod +x tests/client/rekey-t])
AC_CONFIG_COMMANDS([tests/config],
    [test -d tests/config || mkdir tests/config])
AC_OUTPUT
