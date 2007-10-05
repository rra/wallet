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
    struct remctl_output *output;
    char *data = NULL;
    size_t length = 0;
    int status = 255;

    /* Run the command on the wallet server */
    command[0] = type;
    command[1] = "get";
    command[2] = "keytab";
    command[3] = name;
    command[4] = NULL;
    if (!remctl_command(r, command))
        die("%s", remctl_error(r));

    /* Retrieve the results. */
    do {
        output = remctl_output(r);
        switch (output->type) {
        case REMCTL_OUT_OUTPUT:
            if (output->stream == 1) {
                data = xrealloc(data, length + output->length);
                memcpy(data + length, output->data, output->length);
                length += output->length;
            } else {
                fprintf(stderr, "wallet: ");
                fwrite(output->data, 1, output->length, stderr);
            }
            break;
        case REMCTL_OUT_STATUS:
            status = output->status;
            break;
        case REMCTL_OUT_ERROR:
            fprintf(stderr, "wallet: ");
            fwrite(output->data, 1, output->length, stderr);
            fputc('\n', stderr);
            exit(255);
        case REMCTL_OUT_DONE:
            break;
        }
    } while (output->type != REMCTL_OUT_DONE);
    if (status != 0)
        exit(status);

    /* Okay, we now have the valid keytab data in data.  Write it out. */
    write_file(file, data, length);
}
