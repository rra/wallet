/*  $Id$
**
**  Internal support functions for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007 Board of Trustees, Leland Stanford Jr. University
**
**  See README for licensing terms.
*/

#ifndef CLIENT_INTERNAL_H
#define CLIENT_INTERNAL_H 1

/* __attribute__ is available in gcc 2.5 and later, but only with gcc 2.7
   could you use the __format__ form of the attributes, which is what we use
   (to avoid confusion with other macros). */
#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __attribute__(spec)   /* empty */
# endif
#endif

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED  __attribute__((__unused__))

/* BEGIN_DECLS is used at the beginning of declarations so that C++
   compilers don't mangle their names.  END_DECLS is used at the end. */
#undef BEGIN_DECLS
#undef END_DECLS
#ifdef __cplusplus
# define BEGIN_DECLS    extern "C" {
# define END_DECLS      }
#else
# define BEGIN_DECLS    /* empty */
# define END_DECLS      /* empty */
#endif

/* Temporary until we have some real configuration. */
#ifndef SERVER
# define SERVER "wallet.stanford.edu"
#endif
#ifndef PORT
# define PORT 4444
#endif

BEGIN_DECLS

/* Given a srvtab file, the Kerberos v5 principal, and the keytab file, write
   a srvtab file for the corresponding Kerberos v4 principal. */
void write_srvtab(const char *srvtab, const char *principal,
                  const char *keytab);

END_DECLS

#endif /* !CLIENT_INTERNAL_H */
