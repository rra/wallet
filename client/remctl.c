/*  $Id$
**
**  remctl interface for the wallet client.
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
**  Given a remctl connection and a command, run the command.
**
**  If data is non-NULL, save the output in it and return the length in
**  length.  Otherwise, send any output to stdout.  Either way, send error
**  output to stderr, and return the exit status (or 255 if there is an
**  error).
*/
int
run_command(struct remctl *r, const char **command, char **data,
            size_t *length)
{
    struct remctl_output *output;
    int status = 255;

    if (data != NULL)
        *data = NULL;
    if (length != NULL)
        *length = 0;
    if (!remctl_command(r, command)) {
        warn("%s", remctl_error(r));
        return 255;
    }
    do {
        output = remctl_output(r);
        switch (output->type) {
        case REMCTL_OUT_OUTPUT:
            if (output->stream == 1) {
                if (data != NULL) {
                    *data = xrealloc(*data, *length + output->length);
                    memcpy(*data + *length, output->data, output->length);
                    *length += output->length;
                } else {
                    fwrite(output->data, 1, output->length, stdout);
                }
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
            status = 255;
            break;
        case REMCTL_OUT_DONE:
            break;
        }
    } while (output->type != REMCTL_OUT_DONE);
    return status;
}
