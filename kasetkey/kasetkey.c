/*  $Id$
**
**  Create or change a principal and/or generate a srvtab.
**
**  Written by Roland Schemers <schemers@stanford.edu>
**  Updated by Russ Allbery <rra@stanford.edu>
**  Updated again by AAU, Anton Ushakov  <antonu@stanford.edu>
**  Copyright 1994, 1998, 1999, 2000, 2006, 2007
**      Board of Trustees, Leland Stanford Jr. University
**
**  Sets the key of a principal in the AFS kaserver given a srvtab.  This
**  program is now used for synchronization of K5 and K4 and nothing else.
**  It will no longer be used once K4 is retired.
*/

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <afs/stds.h>
#include <afs/kauth.h>
#include <afs/kautils.h>
#include <afs/cellconfig.h>

/* Normally set by the AFS libraries. */
#ifndef SNAME_SZ
# define SNAME_SZ       40
# define INST_SZ        40
# define REALM_SZ       40
#endif

/* The name of the program, for error reporting. */
static const char *program = NULL;

/* Some global state information. */
struct config {
    char *local_cell;
    int debug;                  /* Whether to enable debugging. */
    int init;                   /* Keyfile initialization. */
    int random;                 /* Randomize the key. */
    char *keyfile;              /* Name of srvtab to use. */
    char *admin;                /* Name of ADMIN user to use. */
    char *password;             /* Password to use. */
    char *srvtab;               /* srvtab file to generate. */
    char *service;              /* Service principal to create. */
    char *delete;               /* Service principal to delete. */
    char *k5srvtab;             /* K5 converted srvtab to read for key. */
};

/* Usage message.  Pass in the program name four times. */
static const char usage_message[] = "\
Usage: %s [options]\n\
  -a adminuser     Admin user\n\
  -c k5srvtab      Use the key from the given srvtab (for sync w/ K5)\n\
  -D service       Name of service to delete\n\
  -d               turn on debugging\n\
  -f srvtab        Name of srvtab file to create\n\
  -h               This help\n\
  -i               Initialize DES key file\n\
  -k keyfile       File containing srvtab for admin user\n\
  -p password      Use given password to create key\n\
  -r               Use random key\n\
  -s service       Name of service to create\n\
  -v               Print version\n\
\n\
To create a srvtab for rcmd.slapshot and be prompted for the admin\n\
passowrd:\n\
\n\
    %s -f srvtab.rcmd.slapshot -s rcmd.slapshot -r\n\
\n\
To create a srvtab from within a script you must stash the DES key\n\
in a srvtab with:\n\
\n\
    %s -a admin -i -k /.adminkey\n\
\n\
and then create a srvtab for rcmd.slapshot with:\n\
\n\
    %s -k /.adminkey -a admin -r -f srvtab -s rcmd.slapshot\n\
\n";


/* Report a fatal error. */
static void
die(const char *format, ...)
{
    va_list args;

    if (program != NULL)
        fprintf(stderr, "%s: ", program);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    exit(1);
}


/* Report a fatal error, including strerror information. */
static void
sysdie(const char *format, ...)
{
    int oerrno;
    va_list args;

    oerrno = errno;
    if (program != NULL)
        fprintf(stderr, "%s: ", program);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, ": %s\n", strerror(oerrno));
    exit(1);
}


/*
 * Print out the usage message and then exit with the status given as the only
 * argument.  If status is zero, the message is printed to standard output;
 * otherwise, it is sent to standard error.
 */
static void
usage(int status)
{
    if (program == NULL)
        program = "";
    fprintf((status == 0) ? stdout : stderr, usage_message,
            program, program, program, program);
    exit(status);
}


/*
 * Parse a principal name into name, inst, and cell, filling in the cell from
 * local_cell if none was given.
 */
static void
parse_principal(struct config *config, char *principal, char *name,
                char *inst, char *cell)
{
    long code;

    code = ka_ParseLoginName(principal, name, inst, cell);
    if (config->debug)
        printf("ka_ParseLoginName %ld\n", code);
    if (code != 0)
        die("can't parse principal %s", principal);
    if (cell[0] == '\0') {
        strncpy(cell, config->local_cell, MAXKTCREALMLEN - 1);
        cell[MAXKTCREALMLEN - 1] = '\0';
    }
}


/*
 * Given a srvtab file name, the principal, the kvno, and the key, write out a
 * new srvtab file.  Dies on any error.
 */
static void
write_srvtab(const char *filename, const char *name, const char *inst,
             char *cell, unsigned char kvno, struct ktc_encryptionKey *key)
{
    char realm[MAXKTCREALMLEN];
    int fd, local;

    if (ka_CellToRealm(cell, realm, &local) == KANOCELL)
        die("unable to determine realm");
    fd = open(filename, O_WRONLY | O_CREAT, 0600);
    if (fd == -1)
        sysdie("can't create srvtab %s", filename);
    if (write(fd, name, strlen(name) + 1) != strlen(name) + 1)
        sysdie("can't write to srvtab %s", filename);
    if (write(fd, inst, strlen(inst) + 1) != strlen(inst) + 1)
        sysdie("can't write to srvtab %s", filename);
    if (write(fd, realm, strlen(realm) + 1) != strlen(realm) + 1)
        sysdie("can't write to srvtab %s", filename);
    if (write(fd, &kvno, 1) != 1)
        sysdie("can't write to srvtab %s", filename);
    if (write(fd, key, sizeof(*key)) != sizeof(*key))
        sysdie("can't write to srvtab %s", filename);
    if (close(fd) != 0)
        sysdie("can't close srvtab %s", filename);
}


/*
 * Initialize a DES keyfile from a password.  If the password wasn't given via
 * a command-line option, prompt for it.
 */
static void
initialize_admin_srvtab(struct config *config)
{
    struct ktc_encryptionKey key;
    char name[MAXKTCNAMELEN];
    char inst[MAXKTCNAMELEN];
    char cell[MAXKTCNAMELEN];
    long code;

    if (config->keyfile == NULL || config->admin == NULL)
        usage(1);

    /* Get the password, one way or another. */
    parse_principal(config, config->admin, name, inst, cell);
    if (config->password != NULL) {
        ka_StringToKey(config->password, cell, &key);
        memset(config->password, 0, strlen(config->password));
    } else {
        char buffer[MAXKTCNAMELEN * 3 + 40];

        sprintf(buffer,"password for %s: ", config->admin);
        code = ka_ReadPassword(buffer, 1, cell, &key);
        if (code != 0)
            die("can't read password");
    }

    /* Create the admin srvtab, removing any old one if one exists. */
    unlink(config->keyfile);
    write_srvtab(config->keyfile, name, inst, cell, 0, &key);
    exit(0);
}


/*
 * Takes the configuration struct and obtains an admin token, which it stores
 * in the second parameter.  Dies on any failure.
 */
static void
authenticate(struct config *config, struct ktc_token *token)
{
    char name[MAXKTCNAMELEN];
    char inst[MAXKTCNAMELEN];
    char cell[MAXKTCNAMELEN];
    char realm[MAXKTCREALMLEN];
    long code;
    int local;
    struct ktc_encryptionKey key;

    /* Get the admin password one way or the other. */
    parse_principal(config, config->admin, name, inst, cell);
    if (ka_CellToRealm(cell, realm, &local) == KANOCELL)
        die("unable to determine realm");
    if (config->keyfile) {
        code = read_service_key(name, inst, realm, 0, config->keyfile,
                                (char *) &key);
        if (config->debug)
            printf("read_service_key %ld\n", code);
        if (code != 0)
            die("can't get key for %s.%s@%s from srvtab %s", name, inst,
                realm, config->keyfile);
    } else {
        char buffer[MAXKTCNAMELEN * 3 + 40];

        sprintf(buffer, "password for %s: ", config->admin);
        code = ka_ReadPassword(buffer, 0, cell, &key);
        if (code)
            die("can't read password");
    }

    /* Now, get the admin token. */
    code = ka_GetAdminToken(name, inst, cell, &key, 300, token, 1);
    memset(&key, 0, sizeof(key));
    if (config->debug)
        printf("ka_GetAdminToken %ld\n", code);
    if (code != 0)
        die("can't get admin token");
}


/* Delete a principal out of the AFS kaserver. */
void
delete_principal(struct config *config)
{
    struct ktc_token token;
    struct ubik_client *conn;
    char name[MAXKTCNAMELEN];
    char inst[MAXKTCNAMELEN];
    char cell[MAXKTCNAMELEN];
    long code;

    /* Make connection to AuthServer. */
    authenticate(config, &token);
    code = ka_AuthServerConn(cell, KA_MAINTENANCE_SERVICE, &token, &conn);
    if (config->debug)
        printf("ka_AuthServerConn %ld\n", code);
    if (code != 0)
        die("can't make connection to auth server");

    /* Delete the user. */
    parse_principal(config, config->delete, name, inst, cell);
    code = ubik_Call(KAM_DeleteUser, conn, 0, name, inst);
    if (config->debug)
        printf("ubik_Call KAM_DeleteUser %ld\n", code);
    if (code != 0 && code != KANOENT)
        die("can't delete existing instance");
    code = ubik_ClientDestroy(conn);
    exit(0);
}


/*
 * Create a new principal in the AFS kaserver (deleting it and recreating it
 * if it already exists) with either the indicated key or with a random key,
 * and then write out a srvtab for that principal.  Also supported is reading
 * the key from an existing srvtab (likely created via Kerberos v5 kadmin from
 * a keytab).
 */
void
generate_srvtab(struct config *config)
{
    struct ktc_token token;
    struct ubik_client *conn;
    char name[MAXKTCNAMELEN];
    char inst[MAXKTCNAMELEN];
    char cell[MAXKTCNAMELEN];
    long code;
    struct ktc_encryptionKey key;

    /* Make connection to AuthServer. */
    authenticate(config, &token);
    code = ka_AuthServerConn(cell, KA_MAINTENANCE_SERVICE, &token, &conn);
    if (config->debug)
        printf("ka_AuthServerConn %ld\n", code);
    if (code != 0)
        die("can't make connection to auth server");

    /* Get the key for the principal we're creating. */
    parse_principal(config, config->service, name, inst, cell);
    if (config->k5srvtab != NULL) { 
        char buffer[SNAME_SZ * 4];
        char *p;
        char sname[SNAME_SZ];
        char sinst[INST_SZ];
        char srealm[REALM_SZ];
        unsigned char kvno;
        FILE *srvtab;

        /* Read the whole converted srvtab into memory. */
        srvtab = fopen(config->k5srvtab, "r");
        if (srvtab == NULL)
            sysdie("can't open converted srvtab %s", config->k5srvtab);
        if (fgets(buffer, sizeof(buffer), srvtab) == NULL)
            sysdie("can't read converted srvtab %s", config->k5srvtab);
        fclose(srvtab);

        /* Now parse it.  Fields are delimited by NUL. */
        strncpy(sname, p, SNAME_SZ - 1);
        sname[sizeof(sname) - 1] = '\0';
        p += strlen(sname) + 1;
        strncpy(sinst, p, INST_SZ - 1);
        sinst[sizeof(sinst) - 1] = '\0';
        p += strlen(sinst) + 1;
        strncpy(srealm, p, REALM_SZ - 1);
        srealm[sizeof(srealm) - 1] = '\0';
        p += strlen(srealm) + 1;
        memcpy(&kvno, p, sizeof(unsigned char));
        p += sizeof(unsigned char);
        memcpy(key.data, p, sizeof(key));
        memset(buffer, 0, sizeof(buffer));
    } else if (config->random) {
        code = ubik_Call(KAM_GetRandomKey, conn, 0, &key);
        if (config->debug)
            printf("ka_AuthServerConn %ld\n", code);
        if (code != 0)
            die("can't get random key");
    } else {
        code = ka_ReadPassword("service password: ", 1, cell, &key);
        if (code != 0)
            die("can't read password");
    }

    /*
     * Now, we have the key.  Try to create the principal.  If it already
     * exists, try deleting it first and then creating it again.
     */
    code = ubik_Call(KAM_CreateUser, conn, 0, name, inst, key);
    if (config->debug)
        printf("ubik_Call KAM_CreateUser %ld\n", code);
    if (code == KAEXIST) {
        code = ubik_Call(KAM_DeleteUser, conn, 0, name, inst);
        if (config->debug)
            printf("ubik_Call KAM_DeleteUser %ld\n", code);
        if (code != 0)
            die("can't delete existing instance");
        code = ubik_Call(KAM_CreateUser, conn, 0, name, inst, key);
        if (config->debug)
            printf("ubik_Call KAM_CreateUser %ld\n", code);
    }
    if (code != 0)
        die("can't create user");
    code = ubik_ClientDestroy (conn);

    /* Create the srvtab file.  Don't bother if we have a converted one. */
    if (config->srvtab && !config->k5srvtab) {
        char realm[MAXKTCREALMLEN];
        int local;
        unsigned char kvno = 0;
        int sfd;

        if (ka_CellToRealm(cell, realm, &local) == KANOCELL)
            die("unable to determine realm");

        /* Make a backup copy of any existing one, just in case. */
        if (access(config->srvtab, F_OK) == 0) {
            char backup[MAXPATHLEN];

            snprintf(backup, sizeof(backup), "%s.bak", config->srvtab);
            if (rename(config->srvtab, backup) != 0)
                sysdie("can't create backup srvtab %s", backup);
        }
        write_srvtab(config->srvtab, name, inst, cell, kvno, &key);
    }
    memset(&key, 0, sizeof(key));
    exit(0);
}


int
main(int argc, char *argv[])
{
    long code;
    int opt;
    struct config config;
 
    /* Initialize, get our local cell, etc. */
    memset(&config, 0, sizeof(config));
    program = argv[0];
    code = ka_Init(0);
    config.local_cell = ka_LocalCell();
    if (config.local_cell == NULL || code != 0)
        die("can't initialize");

    /* Parse options. */
    while ((opt = getopt(argc, argv, "a:c:D:df:hik:p:rs:v")) != EOF) {
        switch (opt) {
        case 'a': config.admin = optarg;        break;
        case 'c': config.k5srvtab = optarg;     break;
        case 'D': config.delete = optarg;       break;
        case 'd': config.debug = 1;             break;
        case 'f': config.srvtab = optarg;       break;
        case 'i': config.init = 1;              break;
        case 'k': config.keyfile = optarg;      break;
        case 'p': config.password = optarg;     break;
        case 'r': config.random = 1;            break;
        case 's': config.service = optarg;      break;

        /* Usage doesn't return. */
        case 'h':
            usage(0);
        case 'v':
            printf("%s: version %s\n", program, PACKAGE_VERSION);
            exit(0);
        default:
            usage(1);
        }
    }

    /* Take the right action. */
    if (config.random && config.k5srvtab)
        usage(1);
    if (config.debug)
        fprintf(stdout,"cell: %s\n", config.local_cell);
    if (config.init)
        initialize_admin_srvtab(&config);
    else if (config.service != NULL)
        generate_srvtab(&config);
    else if (config.delete != NULL)
        delete_principal(&config);
    else
        usage(1);
    exit(0);
}
