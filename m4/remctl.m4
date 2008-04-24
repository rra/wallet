dnl remctl.m4 -- Find the compiler and linker flags for remctl.
dnl $Id$
dnl
dnl This file provides RRA_LIB_REMCTL, which finds the compiler and linker
dnl flags for linking with remctl libraries and sets the substitution
dnl variables REMCTL_CPPFLAGS, REMCTL_LDFLAGS, and REMCTL_LIBS.  Also provides
dnl RRA_LIB_REMCTL_SET to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl remctl libraries; RRA_LIB_REMCTL_SWITCH to do the same but save the
dnl current values first; and RRA_LIB_REMCTL_RESTORE to restore those settings
dnl to before the last RRA_LIB_REMCTL_SWITCH.
dnl
dnl This macro depends on RRA_ENABLE_REDUCED_DEPENDS and RRA_LIB_GSSAPI.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2008 Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

dnl Set CPPFLAGS, LDFLAGS, and LIBS to values including the Kerberos v5
dnl settings.
AC_DEFUN([RRA_LIB_REMCTL_SET],
[CPPFLAGS="$REMCTL_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$REMCTL_LDFLAGS $LDFLAGS"
 LIBS="$REMCTL_LIBS $LIBS"])

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Kerberos v5 flags.  Used as a wrapper, with
dnl RRA_LIB_REMCTL_RESTORE, around tests.
AC_DEFUN([RRA_LIB_REMCTL_SWITCH],
[rra_remctl_save_CPPFLAGS="$CPPFLAGS"
 rra_remctl_save_LDFLAGS="$LDFLAGS"
 rra_remctl_save_LIBS="$LIBS"
 RRA_LIB_REMCTL_SET])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_REMCTL_SWITCH was called).
AC_DEFUN([RRA_LIB_REMCTL_RESTORE],
[CPPFLAGS="$rra_remctl_save_CPPFLAGS"
 LDFLAGS="$rra_remctl_save_LDFLAGS"
 LIBS="$rra_remctl_save_LIBS"])

dnl Set REMCTL_CPPFLAGS and REMCTL_LDFLAGS based on rra_remctl_root.
AC_DEFUN([_RRA_LIB_REMCTL_PATHS],
[AS_IF([test x"$rra_remctl_root" != x],
    [AS_IF([test x"$rra_remctl_root" != x/usr],
        [REMCTL_CPPFLAGS="-I${rra_remctl_root}/include"])
     REMCTL_LDFLAGS="-L${rra_remctl_root}/lib"])])

dnl The main macro.
AC_DEFUN([RRA_LIB_REMCTL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_remctl_root=
 REMCTL_CPPFLAGS=
 REMCTL_LDFLAGS=
 REMCTL_LIBS=
 AC_SUBST([REMCTL_CPPFLAGS])
 AC_SUBST([REMCTL_LDFLAGS])
 AC_SUBST([REMCTL_LIBS])
 AC_ARG_WITH([remctl],
    [AC_HELP_STRING([--with-remctl=DIR],
        [Location of remctl headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_remctl_root="$withval"])])
 _RRA_LIB_REMCTL_PATHS
 AS_IF([test x"$rra_reduced_depends" = xtrue],
    [REMCTL_LIBS="-lremctl"],
    [RRA_LIB_GSSAPI
     REMCTL_CPPFLAGS="$REMCTL_CPPFLAGS $GSSAPI_CPPFLAGS"
     REMCTL_LDFLAGS="$REMCTL_LDFLAGS $GSSAPI_LDFLAGS"
     REMCTL_LIBS="-lremctl $GSSAPI_LIBS"])])
