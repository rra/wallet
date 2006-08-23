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
#include <system.h>

#include <errno.h>
#include <fcntl.h>

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
Usage: wallet [options] (get|show) <object> <name>\n\
\n\
Options:\n\
    -c <command>    Command prefix to use (default: wallet)\n\
    -k <principal>  Kerberos principal of the server\n\
    -h              Display this help\n\
    -p <port>       Port of server (default: 4444)\n\
    -s <server>     Server hostname (default: " SERVER "\n\
    -v              Display the version of remctl\n";


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
    const char *command[5];
    struct remctl_result *result;
    const char *server = SERVER;
    const char *principal = NULL;
    unsigned short port = PORT;
    long tmp;
    char *end;

    command[0] = "wallet";
    while ((option = getopt(argc, argv, "c:k:hp:s:v")) != EOF) {
        switch (option) {
        case 'c':
            command[0] = optarg;
            break;
        case 'k':
            principal = optarg;
            break;
        case 'h':
            usage(0);
            break;
        case 'p':
            errno = 0;
            tmp = strtol(optarg, &end, 10);
            if (tmp <= 0 || tmp > 65535 || *end != '\0') {
                fprintf(stderr, "Invalid port number %s\n", optarg);
                exit(1);
            }
            port = tmp;
        case 's':
            server = optarg;
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

    /* Perform the desired operation based on the first argument. */
    if (strcmp(argv[0], "get") == 0) {
        command[1] = "get";
    } else if (strcmp(argv[0], "show") == 0) {
        command[1] = "show";
    }
    command[2] = argv[1];
    command[3] = argv[2];
    command[4] = NULL;
    result = remctl(server, port, principal, command);

    /* Display the results. */
    if (result->error != NULL) {
        fprintf(stderr, "%s\n", result->error);
    } else if (result->stderr_len > 0) {
        fwrite(result->stderr_buf, 1, result->stderr_len, stderr);
    } else if (strcmp(command[1], "get") == 0) {
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
    } else {
        fwrite(result->stdout_buf, 1, result->stdout_len, stdout);
    }
    exit(result->status);
}
