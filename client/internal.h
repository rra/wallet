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

#include <sys/types.h>
#include <util/util.h>

/* Forward declarations to avoid unnecessary includes. */
struct remctl;

/* Temporary until we have some real configuration. */
#ifndef SERVER
# define SERVER "wallet.stanford.edu"
#endif
#ifndef PORT
# define PORT 4444
#endif

BEGIN_DECLS

/* Given a remctl object, run a remctl command.  If data is non-NULL, saves
   the standard output from the command into data with the length in length.
   Otherwise, prints it to standard output.  Either way, prints standard error
   output and errors to standard error and returns the exit status or 255 for
   a remctl internal error. */
int run_command(struct remctl *, const char **command, char **data,
                size_t *length);

/* Given a remctl object, the type for the wallet interface, the name of a
   keytab object, and a file name, call the correct wallet commands to
   download a keytab and write it to that file.  If srvtab is not NULL, write
   a srvtab based on the keytab after a successful download. */
int get_keytab(struct remctl *, const char *type, const char *name,
               const char *file, const char *srvtab);

/* Given a filename, some data, and a length, write that data to the given
   file safely and atomically by creating file.new, writing the data, linking
   file to file.bak, and then renaming file.new to file. */
void write_file(const char *name, const void *data, size_t length);

/* Given a srvtab file, the Kerberos v5 principal, and the keytab file, write
   a srvtab file for the corresponding Kerberos v4 principal. */
void write_srvtab(const char *srvtab, const char *principal,
                  const char *keytab);

END_DECLS

#endif /* !CLIENT_INTERNAL_H */
