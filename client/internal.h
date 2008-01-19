/*  $Id$
**
**  Internal support functions for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
**
**  See LICENSE for licensing terms.
*/

#ifndef CLIENT_INTERNAL_H
#define CLIENT_INTERNAL_H 1

#include <krb5.h>
#include <sys/types.h>

#include <util/util.h>

/* Forward declarations to avoid unnecessary includes. */
struct remctl;

/* Temporary until we have some real configuration. */
#ifndef WALLET_SERVER
# define WALLET_SERVER "wallet.stanford.edu"
#endif
#ifndef WALLET_PORT
# define WALLET_PORT 0
#endif

BEGIN_DECLS

/* Given a remctl object, run a remctl command.  If data is non-NULL, saves
   the standard output from the command into data with the length in length.
   Otherwise, prints it to standard output.  Either way, prints standard error
   output and errors to standard error and returns the exit status or 255 for
   a remctl internal error. */
int run_command(struct remctl *, const char **command, char **data,
                size_t *length);

/* Given a remctl object, the type for the wallet interface, object type,
   object name, and a file (which may be NULL), send a wallet get command and
   write the results to the provided file.  If the file is NULL, write the
   results to standard output instead.  Returns 0 on success and an exit
   status on failure. */
int get_file(struct remctl *, const char *prefix, const char *type,
             const char *name, const char *file);

/* Given a remctl object, the Kerberos context, the type for the wallet
   interface, the name of a keytab object, and a file name, call the correct
   wallet commands to download a keytab and write it to that file.  If srvtab
   is not NULL, write a srvtab based on the keytab after a successful
   download. */
int get_keytab(struct remctl *, krb5_context, const char *type,
               const char *name, const char *file, const char *srvtab);

/* Given a filename, some data, and a length, write that data to the given
   file with error checking, overwriting any existing contents. */
void overwrite_file(const char *name, const void *data, size_t length);

/* Given a filename, some data, and a length, write that data to the given
   file safely and atomically by creating file.new, writing the data, linking
   file to file.bak, and then renaming file.new to file. */
void write_file(const char *name, const void *data, size_t length);

/* Given a Kerberos context, a srvtab file, the Kerberos v5 principal, and the
   keytab file, write a srvtab file for the corresponding Kerberos v4
   principal. */
void write_srvtab(krb5_context, const char *srvtab, const char *principal,
                  const char *keytab);

/* Versions of die and warn that report Kerberos errors. */
void die_krb5(krb5_context, krb5_error_code, const char *, ...)
    __attribute__((__noreturn__, __format__(printf, 3, 4)));
void warn_krb5(krb5_context, krb5_error_code, const char *, ...)
    __attribute__((__format__(printf, 3, 4)));

END_DECLS

#endif /* !CLIENT_INTERNAL_H */
