/*
 * Implementation of keytab handling for the wallet client.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2007, 2008, 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <remctl.h>

#include <client/internal.h>
#include <util/concat.h>
#include <util/messages-krb5.h>
#include <util/messages.h>
#include <util/xmalloc.h>

/* List of principals we have already encountered. */
struct principal_name {
    char *princ;
    struct principal_name* next;
};

/*
 * Given a context, a keytab file, and a realm, return a list of all
 * principals in that file.
 */
struct principal_name
keytab_principals(krb5_context ctx, const char *file, char *realm)
{
    char *princname = NULL, *princrealm = NULL;
    bool found;
    krb5_keytab keytab = NULL;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code status;
    struct principal_name *names_seen = NULL, *current_seen = NULL;

    memset(&entry, 0, sizeof(entry));
    status = krb5_kt_resolve(ctx, file, &keytab);
    if (status != 0)
        die_krb5(ctx, status, "cannot open keytab %s", file);
    status = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (status != 0)
        die_krb5(ctx, status, "cannot read keytab %s", file);
    while ((status = krb5_kt_next_entry(ctx, keytab, &entry, &cursor)) == 0) {
        status = krb5_unparse_name(ctx, entry.principal, &princname);
        if (status != 0)
            sysdie("error, cannot unparse name for a principal");

        found = false;
        current_seen = names_seen;
        while (current_seen != NULL) {
            if (strcmp(current_seen->princ, princname)) {
                found = true;
                break;
            }
            current_seen = current_seen->next;
        }

        /* Add any new principals in the correct realm to the list. */
        if (found == false) {
            princrealm = strchr(princname, '@');
            if (princrealm != NULL) {
                *princrealm = '\0';
                princrealm++;
            }
            if (princrealm != NULL && strcmp(princrealm, realm) == 0) {
                current_seen = xmalloc(sizeof(struct principal_name));
                current_seen->princ = xstrdup(princname);
                current_seen->next = names_seen;
                names_seen = current_seen;
            }
        }

        krb5_kt_free_entry(ctx, &entry);
        free(princname);
    }

    if (status != KRB5_KT_END)
        die_krb5(ctx, status, "error reading keytab %s", file);
    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    krb5_kt_close(ctx, keytab);

    /* TODO: Testing the principals correctly made, remove after. */
    warn("Exiting keytab_principals");
    current_seen = names_seen;
    while (current_seen != NULL) {
      warn("found principal %s", current_seen->princ);
      current_seen = current_seen->next;
     }

    return *names_seen;
}

/*
 * Given keytab data as a pointer to memory and a length and the path of a
 * second keytab, merge the keys in the memory keytab into the file keytab.
 * Currently, this doesn't do any cleanup of old kvnos and doesn't handle
 * duplicate kvnos correctly.  Dies on any error.
 */
static void
merge_keytab(krb5_context ctx, const char *newfile, const char *file)
{
    char *oldfile;
    krb5_keytab old = NULL, temp = NULL;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code status;

    memset(&entry, 0, sizeof(entry));
    oldfile = concat("WRFILE:", file, (char *) 0);
    status = krb5_kt_resolve(ctx, oldfile, &old);
    if (status != 0)
        die_krb5(ctx, status, "cannot open keytab %s", file);
    free(oldfile);
    status = krb5_kt_resolve(ctx, newfile, &temp);
    if (status != 0)
        die_krb5(ctx, status, "cannot open temporary keytab %s", newfile);
    status = krb5_kt_start_seq_get(ctx, temp, &cursor);
    if (status != 0)
        die_krb5(ctx, status, "cannot read temporary keytab %s", newfile);
    while ((status = krb5_kt_next_entry(ctx, temp, &entry, &cursor)) == 0) {
        status = krb5_kt_add_entry(ctx, old, &entry);
        if (status != 0)
            die_krb5(ctx, status, "cannot write to keytab %s", file);
        krb5_kt_free_entry(ctx, &entry);
    }
    if (status != KRB5_KT_END)
        die_krb5(ctx, status, "error reading temporary keytab %s", newfile);
    krb5_kt_end_seq_get(ctx, temp, &cursor);
    if (old != NULL)
        krb5_kt_close(ctx, old);
    if (temp != NULL)
        krb5_kt_close(ctx, temp);
}

/*
 * Given a remctl object, the type and name of a keytab object, and
 * references to keytab data and data length, call the correct wallet
 * commands to download a keytab and return the keytab data.  Returns the
 * status of the remctl command.
 */
int
download_keytab(struct remctl *r, const char *type, const char *name,
                char **data, size_t *length)
{
    const char *command[5];
    int status;

    command[0] = type;
    command[1] = "get";
    command[2] = "keytab";
    command[3] = name;
    command[4] = NULL;
    status = run_command(r, command, data, length);
    if (*data == NULL) {
        warn("no data returned by wallet server");
        return 255;
    }
    return status;
}

/*
 * Given a remctl object, the Kerberos context, the name of a keytab object,
 * and a file name, call the correct wallet commands to download a keytab and
 * write it to that file.  Returns the status or 255 on an internal error.
 */
int
get_keytab(struct remctl *r, krb5_context ctx, const char *type,
           const char *name, const char *file, const char *srvtab)
{
    const char *command[5];
    char *tempfile;
    char *data = NULL;
    size_t length = 0;
    int status;

    command[0] = type;
    command[1] = "get";
    command[2] = "keytab";
    command[3] = name;
    command[4] = NULL;
    status = run_command(r, command, &data, &length);
    if (status != 0)
        return status;
    if (data == NULL) {
        warn("no data returned by wallet server");
        return 255;
    }
    if (access(file, F_OK) == 0) {
        tempfile = concat(file, ".new", (char *) 0);
        overwrite_file(tempfile, data, length);
        if (srvtab != NULL)
            write_srvtab(ctx, srvtab, name, tempfile);
        merge_keytab(ctx, tempfile, file);
        if (unlink(tempfile) < 0)
            sysdie("unlink of temporary keytab file %s failed", tempfile);
        free(tempfile);
    } else {
        write_file(file, data, length);
        if (srvtab != NULL)
            write_srvtab(ctx, srvtab, name, file);
    }
    return 0;
}

/*
 * Given a remctl object, the Kerberos context, the type and name of a keytab
 * object, and a file name, iterate through every existing principal in the
 * keytab, get fresh keys for those principals, and save the old and new
 * keys to that file.  Returns the status, or 255 on an internal error.
 */
int
rekey_keytab(struct remctl *r, krb5_context ctx, const char *type,
             const char *file)
{
    char *realm = NULL;
    char *data = NULL;
    char *tempfile, *backupfile;
    size_t length = 0;
    int status;
    bool error = false, rekeyed = false;
    struct principal_name *names_seen, *current_seen;

    tempfile = concat(file, ".new", (char *) 0);

    krb5_get_default_realm(ctx, &realm);
    *names_seen = keytab_principals(ctx, file, realm);
    /* keytab_principals(ctx, file, realm); */

    /* TODO: Testing we got back the principals correctly, delete. */
    warn("Finished keytab_principals");
    current_seen = names_seen;
    while (current_seen != NULL) {
        warn("found principal %s", current_seen->princ);
        current_seen = current_seen->next;
    }
    return 0;

    current_seen = names_seen;
    while (current_seen != NULL) {
        status = download_keytab(r, type, current_seen->princ, &data,
                                 &length);
        if (status != 0) {
            warn("error rekeying for principal %s", current_seen->princ);
            error = true;
        } else {
            if (data != NULL) {
                append_file(tempfile, data, length);
                rekeyed = true;
            }
        }
        warn("seen principal %s", current_seen->princ);
        current_seen = current_seen->next;
    }

    /* If no new keytab data, then leave the keytab as-is. */
    if (rekeyed == false)
        sysdie("no rekeyed principals found");

    /* Now merge the original keytab file with the one containing the new. */
    if (access(file, F_OK) == 0) {

        /* If error, first copy the keytab file to filename.old */
        if (error == true) {
            data = read_file(file, &length);
            backupfile = concat(file, ".old", (char *) 0);
            overwrite_file(backupfile, data, length);
        }
        merge_keytab(ctx, tempfile, file);
    } else {
        data = read_file(tempfile, &length);
        write_file(file, data, length);
    }
    if (unlink(tempfile) < 0)
      sysdie("unlink of temporary keytab file %s failed", tempfile);
    free(tempfile);
    return 0;
}
