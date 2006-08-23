/*  $Id: clibrary.h 7121 2005-01-06 00:40:37Z rra $
**
**  Declarations of routines and variables in the C library.  Including this
**  file is the equivalent of including all of the following headers,
**  portably:
**
**      #include <sys/types.h>
**      #include <stdarg.h>
**      #include <stdio.h>
**      #include <stdlib.h>
**      #include <stddef.h>
**      #include <string.h>
**      #include <unistd.h>
**
**  Missing functions are provided via #define or prototyped if available from
**  the util helper library.  Also provides some standard #defines.
*/

#ifndef SYSTEM_H
#define SYSTEM_H 1

/* Make sure we have our configuration information. */
#include <config.h>

/* A set of standard ANSI C headers.  We don't care about pre-ANSI systems. */
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

/* __attribute__ is available in gcc 2.5 and later, but only with gcc 2.7
   could you use the __format__ form of the attributes, which is what we use
   (to avoid confusion with other macros). */
#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(spec)   /* empty */
# endif
#endif

#endif /* !CLIBRARY_H */
