/*  $Id$
**
**  Implementation of keytab handling for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
**
**  See LICENSE for licensing terms.
*/

#include <config.h>
#include <system.h>

#include <remctl.h>

#include <client/internal.h>
#include <util/util.h>


/*
**  Configure a given keytab to be synchronized with an AFS kaserver if it
**  isn't already.  Returns true on success, false on failure.
*/
static int
set_sync(struct remctl *r, const char *type, const char *name)
{
    const char *command[7];
    char *data = NULL;
    size_t length = 0;
    int status;

    command[0] = type;
    command[1] = "getattr";
    command[2] = "keytab";
    command[3] = name;
    command[4] = "sync";
    command[5] = NULL;
    status = run_command(r, command, &data, &length);
    if (status != 0)
        return 0;
    if (data == NULL || strstr(data, "kaserver\n") == NULL) {
        command[1] = "setattr";
        command[5] = "kaserver";
        command[6] = NULL;
        status = run_command(r, command, NULL, NULL);
        if (status != 0)
            return 0;
    }
    return 1;
}


/*
**  Given a remctl object, the Kerberos context, the name of a keytab object,
**  and a file name, call the correct wallet commands to download a keytab and
**  write it to that file.  Returns the setatus or 255 on an internal error.
*/
int
get_keytab(struct remctl *r, krb5_context ctx, const char *type,
           const char *name, const char *file, const char *srvtab)
{
    const char *command[5];
    char *data = NULL;
    size_t length = 0;
    int status;

    if (srvtab != NULL)
        if (!set_sync(r, type, name))
            return 255;
    command[0] = type;
    command[1] = "get";
    command[2] = "keytab";
    command[3] = name;
    command[4] = NULL;
    status = run_command(r, command, &data, &length);
    if (status != 0)
        return status;
    if (data == NULL) {
        warn("no data returned by wallet server");
        return 255;
    }
    write_file(file, data, length);
    if (srvtab != NULL)
        write_srvtab(ctx, srvtab, name, file);
    return 0;
}
