/*  $Id$
**
**  The client program for the wallet system.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2006 Board of Trustees, Leland Stanford Jr. University
**
**  See README for licensing terms.
*/

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <remctl.h>

/* Temporary until we have some real configuration. */
#ifndef SERVER
# define SERVER "wallet.stanford.edu"
#endif
#ifndef PORT
# define PORT 4444
#endif

/* Usage message. */
static const char usage_message[] = "\
Usage: wallet (get|show) keytab <name>\n\
\n\
Options:\n\
    -h            Display this help\n\
    -v            Display the version of remctl\n";


/*
**  Display the usage message for remctl.
*/
static void
usage(int status)
{
    fprintf((status == 0) ? stdout : stderr, "%s", usage_message);
    exit(status);
}


/*
**  Main routine.  Parse the arguments and then perform the desired
**  operation.
*/
int
main(int argc, char *argv[])
{
    int option, fd;
    ssize_t status;
    const char *command[3];
    struct remctl_result *result;

    while ((option = getopt(argc, argv, "hv")) != EOF) {
        switch (option) {
        case 'h':
            usage(0);
            break;
        case 'v':
            printf("%s\n", PACKAGE_STRING);
            exit(0);
            break;
        default:
            usage(1);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 3)
        usage(1);
    if (strcmp(argv[1], "keytab") != 0)
        usage(1);

    /* Perform the desired operation based on the first argument. */
    if (strcmp(argv[0], "get") == 0) {
        command[0] = "get";
    } else if (strcmp(argv[0], "show") == 0) {
        command[0] = "show";
    }
    command[1] = "keytab";
    command[2] = argv[2];
    result = remctl(SERVER, PORT, NULL, command);

    /* Display the results. */
    if (result->error != NULL) {
        fprintf(stderr, "%s\n", result->error);
    } else if (result->stderr_len > 0) {
        fwrite(result->stderr_buf, 1, result->stderr_len, stderr);
    } else {
        fd = open("keytab", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            fprintf(stderr, "open of keytab failed: %s", strerror(errno));
            exit(1);
        }
        status = write(fd, result->stdout_buf, result->stdout_len);
        if (status < 0) {
            fprintf(stderr, "write to keytab failed: %s", strerror(errno));
            exit(1);
        } else if (status != result->stdout_len) {
            fprintf(stderr, "write to keytab truncated");
            exit(1);
        }
        if (close(fd) < 0) {
            fprintf(stderr, "close of keytab failed: %s", strerror(errno));
            exit(1);
        }
    }
    exit(result->status);
}
