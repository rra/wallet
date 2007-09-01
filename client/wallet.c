/*  $Id$
**
**  The client program for the wallet system.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
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
Usage: wallet [options] <command> <type> <name> [<arg> ...]\n\
       wallet [options] acl <command> <id> [<arg> ...]\n\
\n\
Options:\n\
    -c <command>    Command prefix to use (default: wallet)\n\
    -f <output>     For the get command, output file (default: stdout)\n\
    -k <principal>  Kerberos principal of the server\n\
    -h              Display this help\n\
    -p <port>       Port of server (default: 4444)\n\
    -S <srvtab>     For the get keytab command, srvtab output file\n\
    -s <server>     Server hostname (default: " SERVER "\n\
    -v              Display the version of wallet\n";


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
    const char **command;
    struct remctl_result *result;
    const char *type = "wallet";
    const char *server = SERVER;
    const char *principal = NULL;
    unsigned short port = PORT;
    const char *file = NULL;
    const char *srvtab = NULL;
    int i;
    long tmp;
    char *end;

    while ((option = getopt(argc, argv, "c:f:k:hp:S:s:v")) != EOF) {
        switch (option) {
        case 'c':
            type = optarg;
            break;
        case 'f':
            file = optarg;
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
            break;
        case 'S':
            srvtab = optarg;
            break;
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
    if (argc < 3)
        usage(1);

    /* -f is only supported for get and -S with get keytab. */
    if (file != NULL && strcmp(argv[0], "get") != 0) {
        fprintf(stderr, "wallet: -f only supported for get\n");
        exit(1);
    }
    if (srvtab != NULL)
        if (strcmp(argv[0], "get") != 0 || strcmp(argv[1], "keytab") != 0) {
            fprintf(stderr, "wallet: -S only supported for get keytab\n");
            exit(1);
        }

    /* Allocate space for the command to send to the server. */
    command = malloc(sizeof(char *) * (argc + 2));
    if (command == NULL) {
        fprintf(stderr, "wallet: cannot allocate memory: %s", strerror(errno));
        exit(1);
    }
    command[0] = type;
    for (i = 0; i < argc; i++)
        command[i + 1] = argv[i];
    command[argc + 1] = NULL;

    /* Run the command. */
    result = remctl(server, port, principal, command);
    free(command);
    if (result == NULL) {
        fprintf(stderr, "wallet: cannot allocate memory: %s", strerror(errno));
        exit(1);
    }

    /* Display the results. */
    if (result->error != NULL) {
        fprintf(stderr, "wallet: %s\n", result->error);
    } else if (result->stderr_len > 0) {
        fprintf(stderr, "wallet: ");
        fwrite(result->stderr_buf, 1, result->stderr_len, stderr);
    } else if (file != NULL && strcmp(command[1], "get") == 0) {
        fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            fprintf(stderr, "open of %s failed: %s", file, strerror(errno));
            exit(1);
        }
        status = write(fd, result->stdout_buf, result->stdout_len);
        if (status < 0) {
            fprintf(stderr, "write to %s failed: %s", file, strerror(errno));
            exit(1);
        } else if (status != (ssize_t) result->stdout_len) {
            fprintf(stderr, "write to %s truncated", file);
            exit(1);
        }
        if (close(fd) < 0) {
            fprintf(stderr, "close of %s failed: %s", file, strerror(errno));
            exit(1);
        }
    } else {
        fwrite(result->stdout_buf, 1, result->stdout_len, stdout);
    }
    exit(result->status);
}
