/*  $Id$
**
**  Implementation of keytab handling for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007 Board of Trustees, Leland Stanford Jr. University
**
**  See README for licensing terms.
*/

#include <config.h>
#include <system.h>

#include <remctl.h>

#include <client/internal.h>
#include <util/util.h>

/*
**  Given a remctl object, the name of a keytab object, and a file name, call
**  the correct wallet commands to download a keytab and write it to that
**  file.
*/
void
get_keytab(struct remctl *r, const char *type, const char *name,
           const char *file)
{
    const char *command[5];
    char *data = NULL;
    size_t length = 0;
    int status = 255;

    command[0] = type;
    command[1] = "get";
    command[2] = "keytab";
    command[3] = name;
    command[4] = NULL;
    status = run_command(r, command, &data, &length);
    if (status != 0)
        exit(status);
    if (data == NULL)
        die("no data returned by wallet server");
    write_file(file, data, length);
}
