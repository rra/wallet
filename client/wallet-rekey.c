/*
 * A specialized wallet client for rekeying a keytab.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *        and Jon Robertson <jonrober@stanford.edu>
 * Copyright 2018, 2020 Russ Allbery <eagle@eyrie.org>
 * Copyright 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * SPDX-License-Identifier: MIT
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#include <remctl.h>

#include <client/internal.h>
#include <util/messages-krb5.h>
#include <util/messages.h>

/*
 * Usage message.  Use as a format and pass the port number and default server
 * name.
 */
static const char usage_message[] = "\
Usage: wallet-rekey [options] [<file> ...]\n\
\n\
Options:\n\
    -c <command>    Command prefix to use (default: wallet)\n\
    -k <principal>  Kerberos principal of the server\n\
    -h              Display this help\n\
    -p <port>       Port of server (default: %d, if zero, remctl default)\n\
    -s <server>     Server hostname (default: %s)\n\
    -u <user>       Authenticate as <user> before rekeying\n\
    -v              Display the version of wallet\n";


/*
 * Display the usage message for wallet-rekey.
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
    int option, i;
    bool okay = true;
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

    while ((option = getopt(argc, argv, "c:k:hp:S:s:u:v")) != EOF) {
        switch (option) {
        case 'c':
            options.type = optarg;
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
     * Rekey all the keytabs given on the command line, or the system keytab
     * if none were given.
     */
    if (argc == 0)
        okay = rekey_keytab(r, ctx, options.type, "/etc/krb5.keytab");
    else {
        for (i = 0; i < argc; i++) {
            okay = rekey_keytab(r, ctx, options.type, argv[i]);
            if (!okay)
                break;
        }
    }
    remctl_close(r);
    krb5_free_context(ctx);
    if (options.user != NULL)
        kdestroy();
    exit(okay ? 0 : 1);
}
