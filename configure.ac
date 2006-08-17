dnl Process this file with Autoconf to produce a configure script.
dnl $Id$
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2006 Board of Trustees, Leland Stanford Jr. University
dnl
dnl See README for licensing terms.

AC_REVISION($Revision$)
AC_PREREQ(2.57)
AC_INIT([wallet], [1.0], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([tools])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AFS_CPPFLAGS=
AFS_LDFLAGS=
AC_ARG_WITH([afs],
    AC_HELP_STRING([--with-afs=DIR],
        [Prefix for AFS headers and libraries (for kasetkey)]),
    [if test x"$withval" != xno ; then
        AFS_CPPFLAGS="-I${withval}/include"
        AFS_LDFLAGS="-L${withval}/lib"
     fi])
AC_SUBST([AFS_CPPFLAGS])
AC_SUBST([AFS_LDFLAGS])

AC_PROG_CC
AC_PROG_INSTALL
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket], ,
    [AC_CHECK_LIB([nsl], [socket],
        [LIBS="-lnsl -lsocket $LIBS"], , [-lsocket])])

AC_CONFIG_HEADER([config.h])
AC_OUTPUT([Makefile])
