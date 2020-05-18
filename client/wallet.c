/*
 * The client program for the wallet system.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2018, 2020 Russ Allbery <eagle@eyrie.org>
 * Copyright 2006-2008, 2010, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * SPDX-License-Identifier: MIT
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>
#include <portable/uio.h>

#include <assert.h>
#include <errno.h>
#include <remctl.h>

#include <client/internal.h>
#include <util/messages-krb5.h>
#include <util/messages.h>
#include <util/xmalloc.h>

/*
 * Usage message.  Use as a format and pass the port number and default server
 * name.
 */
static const char usage_message[] = "\
Usage: wallet [options] <command> <type> <name> [<arg> ...]\n\
       wallet [options] acl <command> <id> [<arg> ...]\n\
\n\
Options:\n\
    -c <command>    Command prefix to use (default: wallet)\n\
    -f <output>     For the get command, output file (default: stdout)\n\
    -k <principal>  Kerberos principal of the server\n\
    -h              Display this help\n\
    -p <port>       Port of server (default: %d, if zero, remctl default)\n\
    -S <srvtab>     For the get keytab command, srvtab output file\n\
    -s <server>     Server hostname (default: %s)\n\
    -u <user>       Authenticate as <user> before running command\n\
    -v              Display the version of wallet\n";


/*
 * Display the usage message for wallet.
 */
__attribute__((__noreturn__)) static void
usage(int status)
{
    fprintf((status == 0) ? stdout : stderr, usage_message, WALLET_PORT,
            (WALLET_SERVER == NULL) ? "<none>" : WALLET_SERVER);
    exit(status);
}


/*
 * Main routine.  Parse the arguments and then perform the desired operation.
 */
int
main(int argc, char *argv[])
{
    krb5_context ctx;
    krb5_error_code retval;
    struct options options;
    int option, i, status;
    struct iovec *command;
    size_t count, length;
    const char *file = NULL;
    const char *srvtab = NULL;
    struct remctl *r;
    long tmp;
    char *end;

    /* Set up logging and identity. */
    message_program_name = "wallet";

    /* Initialize default configuration. */
    memset(&options, 0, sizeof(options));
    retval = krb5_init_context(&ctx);
    if (retval != 0)
        die_krb5(ctx, retval, "cannot initialize Kerberos");
    default_options(ctx, &options);

    while ((option = getopt(argc, argv, "c:f:k:hp:S:s:u:v")) != EOF) {
        switch (option) {
        case 'c':
            options.type = optarg;
            break;
        case 'f':
            file = optarg;
            break;
        case 'k':
            options.principal = optarg;
            break;
        case 'h':
            usage(0);
        case 'p':
            errno = 0;
            tmp = strtol(optarg, &end, 10);
            if (tmp <= 0 || tmp > 65535 || *end != '\0')
                die("invalid port number %s", optarg);
            options.port = (unsigned short) tmp;
            break;
        case 'S':
            srvtab = optarg;
            break;
        case 's':
            options.server = optarg;
            break;
        case 'u':
            options.user = optarg;
            break;
        case 'v':
            printf("%s\n", PACKAGE_STRING);
            exit(0);
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc < 3)
        usage(1);

    /* -f is only supported for get and store and -S with get keytab. */
    if (file != NULL)
        if (strcmp(argv[0], "get") != 0 && strcmp(argv[0], "store") != 0)
            die("-f only supported for get and store");
    if (srvtab != NULL) {
        if (strcmp(argv[0], "get") != 0 || strcmp(argv[1], "keytab") != 0)
            die("-S only supported for get keytab");
        if (file == NULL)
            die("-S option requires -f also be used");
    }

    /*
     * If no server was set at configure time and none was set on the command
     * line or with krb5.conf settings, we can't continue.
     */
    if (options.server == NULL)
        die("no server specified in krb5.conf or with -s");

    /* If a user was specified, obtain Kerberos tickets. */
    if (options.user != NULL)
        kinit(ctx, options.user);

    /* Open a remctl connection. */
    r = remctl_new();
    if (r == NULL)
        sysdie("cannot allocate memory");
    if (!remctl_open(r, options.server, options.port, options.principal))
        die("%s", remctl_error(r));

    /*
     * Most commands, we handle ourselves, but get and store commands are
     * special and keytab get commands with -f are doubly special.
     */
    if (strcmp(argv[0], "get") == 0 || strcmp(argv[0], "store") == 0) {
        if (!object_exists(r, options.type, argv[1], argv[2]))
            object_autocreate(r, options.type, argv[1], argv[2]);
    }
    if (strcmp(argv[0], "get") == 0) {
        if (argc > 3)
            die("too many arguments");
        if (strcmp(argv[1], "keytab") == 0 && file != NULL) {
            status = get_keytab(r, ctx, options.type, argv[2], file, srvtab);
        } else {
            status = get_file(r, options.type, argv[1], argv[2], file);
        }
    } else if (strcmp(argv[0], "rekey") == 0) {
        if (argc > 2)
            die("too many arguments");
        status = rekey_keytab(r, ctx, options.type, argv[1]);
    } else {
        count = argc + 1;
        if (strcmp(argv[0], "store") == 0) {
            if (argc > 4)
                die("too many arguments");
            else if (argc < 4)
                count++;
        }
        command = xcalloc(count, sizeof(struct iovec));
        assert(options.type != NULL);
        command[0].iov_base = (char *) options.type;
        command[0].iov_len = strlen(options.type);
        for (i = 0; i < argc; i++) {
            command[i + 1].iov_base = argv[i];
            command[i + 1].iov_len = strlen(argv[i]);
        }
        if (strcmp(argv[0], "store") == 0 && argc < 4) {
            if (file == NULL)
                file = "-";
            command[argc + 1].iov_base = read_file(file, &length);
            command[argc + 1].iov_len = length;
        }
        status = run_commandv(r, command, count, NULL, NULL);
    }
    remctl_close(r);
    krb5_free_context(ctx);
    if (options.user != NULL)
        kdestroy();
    exit(status);
}
