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
#include <remctl.h>

#include <client/internal.h>
#include <util/util.h>

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
    int option, i, status;
    const char **command;
    const char *type = "wallet";
    const char *server = SERVER;
    const char *principal = NULL;
    unsigned short port = PORT;
    const char *file = NULL;
    const char *srvtab = NULL;
    struct remctl *r;
    long tmp;
    char *end;

    /* Set up logging and identity. */
    message_program_name = "wallet";

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
            if (tmp <= 0 || tmp > 65535 || *end != '\0')
                die("invalid port number %s", optarg);
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
    if (file != NULL && strcmp(argv[0], "get") != 0)
        die("-f only supported for get");
    if (srvtab != NULL) {
        if (strcmp(argv[0], "get") != 0 || strcmp(argv[1], "keytab") != 0)
            die("-S only supported for get keytab");
        if (file == NULL)
            die("-S option requires -f also be used");
    }

    /* Open a remctl connection. */
    r = remctl_new();
    if (r == NULL)
        sysdie("cannot allocate memory");
    if (!remctl_open(r, server, port, principal))
        die("%s", remctl_error(r));

    /* Most commands, we handle ourselves, but keytab get commands with -f are
       special. */
    if (strcmp(argv[0], "get") == 0 && strcmp(argv[1], "keytab") == 0) {
        if (argc > 3)
            die("too many arguments");
        status = get_keytab(r, type, argv[2], file, srvtab);
        remctl_close(r);
        exit(status);
    } else {
        command = xmalloc(sizeof(char *) * (argc + 2));
        command[0] = type;
        for (i = 0; i < argc; i++)
            command[i + 1] = argv[i];
        command[argc + 1] = NULL;
        status = run_command(r, command, NULL, NULL);
        remctl_close(r);
        exit(status);
    }

    /* This should never be reached. */
    die("invalid return from wallet server");
}
