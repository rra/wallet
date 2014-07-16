/*
 * remctl interface for the wallet client.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2007, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <remctl.h>

#include <client/internal.h>
#include <util/messages.h>
#include <util/xmalloc.h>


/*
 * Retrieve the results of a remctl command, which should be issued prior to
 * calling this function.  If data is non-NULL, save the output in it and
 * return the length in length.  Otherwise, send any output to stdout.  Either
 * way, send error output to stderr, and return the exit status (or 255 if
 * there is an error).
 */
static int
command_results(struct remctl *r, char **data, size_t *length)
{
    struct remctl_output *output;
    int status = 255;

    if (data != NULL)
        *data = NULL;
    if (length != NULL)
        *length = 0;
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


/*
 * Given a remctl connection and a NULL-terminated array of strings, run the
 * command and return the results using command_results, optionally putting
 * output into the data variable.
 */
int
run_command(struct remctl *r, const char **command, char **data,
            size_t *length)
{
    if (!remctl_command(r, command)) {
        warn("%s", remctl_error(r));
        return 255;
    }
    return command_results(r, data, length);
}


/*
 * Given a remctl connection, an array of iovecs, and the length of the array,
 * run the command and return the results using command_results, optionally
 * putting output into the data variable.
 */
int
run_commandv(struct remctl *r, const struct iovec *command, size_t count,
             char **data, size_t *length)
{
    if (!remctl_commandv(r, command, count)) {
        warn("%s", remctl_error(r));
        return 255;
    }
    return command_results(r, data, length);
}


/*
 * Check whether an object exists using the exists wallet interface.  Returns
 * true if it does, false if it doesn't, and dies on remctl errors.
 */
int
object_exists(struct remctl *r, const char *prefix, const char *type,
              const char *name)
{
    const char *command[5];
    char *data = NULL;
    size_t length;

    command[0] = prefix;
    command[1] = "check";
    command[2] = type;
    command[3] = name;
    command[4] = NULL;
    if (run_command(r, command, &data, &length) != 0)
        exit(1);
    if (length == 4 && strncmp(data, "yes\n", 4) == 0)
        return 1;
    else
        return 0;
}


/*
 * Attempt autocreation of an object.  Dies if autocreation fails.
 */
void
object_autocreate(struct remctl *r, const char *prefix, const char *type,
                  const char *name)
{
    const char *command[5];

    command[0] = prefix;
    command[1] = "autocreate";
    command[2] = type;
    command[3] = name;
    command[4] = NULL;
    if (run_command(r, command, NULL, NULL) != 0)
        exit(1);
}
