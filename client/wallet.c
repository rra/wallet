/*
 * The client program for the wallet system.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2008
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <krb5.h>
#include <remctl.h>

#include <client/internal.h>
#include <util/util.h>

/*
 * Basic wallet behavior options set either on the command line or via
 * krb5.conf.  If set via krb5.conf, we allocate memory for the strings, but
 * we never free them.
 */
struct options {
    char *type;
    char *server;
    char *principal;
    char *user;
    int port;
};

/*
 * Allow defaults to be set for a particular site with configure options if
 * people don't want to use krb5.conf for some reason.
 */
#ifndef WALLET_SERVER
# define WALLET_SERVER NULL
#endif
#ifndef WALLET_PORT
# define WALLET_PORT 0
#endif

/* Usage message.  Use as a format and pass the port number. */
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
    -v              Display the version of wallet\n";


/*
 * Display the usage message for remctl.
 */
static void
usage(int status)
{
    fprintf((status == 0) ? stdout : stderr, usage_message, WALLET_PORT,
            (WALLET_SERVER == NULL) ? "<none>" : WALLET_SERVER);
    exit(status);
}


/*
 * Load a string option from Kerberos appdefaults.  This requires an annoying
 * workaround because one cannot specify a default value of NULL.
 */
static void
default_string(krb5_context ctx, const char *opt, const char *defval,
               char **result)
{
    if (defval == NULL)
        defval = "";
    krb5_appdefault_string(ctx, "wallet", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}


/*
 * Load a number option from Kerberos appdefaults.  The native interface
 * doesn't support numbers, so we actually read a string and then convert.
 */
static void
default_number(krb5_context ctx, const char *opt, int defval, int *result)
{
    char *tmp = NULL;

    krb5_appdefault_string(ctx, "wallet", NULL, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0')
        *result = atoi(tmp);
    else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}


/*
 * Set option defaults and then get krb5.conf configuration, if any, and
 * override the defaults.  Later, command-line options will override those
 * defaults.
 */
static void
set_defaults(krb5_context ctx, struct options *options)
{
    default_string(ctx, "wallet_type", "wallet", &options->type);
    default_string(ctx, "wallet_server", WALLET_SERVER, &options->server);
    default_string(ctx, "wallet_principal", NULL, &options->principal);
    default_number(ctx, "wallet_port", WALLET_PORT, &options->port);
    options->user = NULL;
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
    const char **command;
    const char *file = NULL;
    const char *srvtab = NULL;
    struct remctl *r;
    long tmp;
    char *end;

    /* Set up logging and identity. */
    message_program_name = "wallet";

    /* Initialize default configuration. */
    retval = krb5_init_context(&ctx);
    if (retval != 0)
        die_krb5(ctx, retval, "cannot initialize Kerberos");
    set_defaults(ctx, &options);

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
            break;
        case 'p':
            errno = 0;
            tmp = strtol(optarg, &end, 10);
            if (tmp <= 0 || tmp > 65535 || *end != '\0')
                die("invalid port number %s", optarg);
            options.port = tmp;
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
    } else {
        if (strcmp(argv[0], "store") == 0) {
            if (argc > 4)
                die("too many arguments");
            else if (argc == 4)
                command = xmalloc(sizeof(char *) * (argc + 2));
            else
                command = xmalloc(sizeof(char *) * (argc + 3));
        } else
            command = xmalloc(sizeof(char *) * (argc + 2));
        command[0] = options.type;
        for (i = 0; i < argc; i++)
            command[i + 1] = argv[i];
        if (strcmp(argv[0], "store") == 0 && argc < 4) {
            command[argc + 1] = read_file(file == NULL ? "-" : file);
            command[argc + 2] = NULL;
        } else
            command[argc + 1] = NULL;
        status = run_command(r, command, NULL, NULL);
    }
    remctl_close(r);
    krb5_free_context(ctx);
    if (options.user != NULL)
        kdestroy();
    exit(status);
}
