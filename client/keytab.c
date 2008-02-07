/*  $Id$
**
**  Implementation of keytab handling for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
**
**  See LICENSE for licensing terms.
*/

#include <config.h>
#include <system.h>

#include <remctl.h>

#include <client/internal.h>
#include <util/util.h>


/*
**  Given keytab data as a pointer to memory and a length and the path of a
**  second keytab, merge the keys in the memory keytab into the file keytab.
**  Currently, this doesn't do any cleanup of old kvnos and doesn't handle
**  duplicate kvnos correctly.  Dies on any error.
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
        krb5_free_keytab_entry_contents(ctx, &entry);
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
**  Configure a given keytab to be synchronized with an AFS kaserver if it
**  isn't already.  Returns true on success, false on failure.
*/
static int
set_sync(struct remctl *r, const char *type, const char *name)
{
    const char *command[7];
    char *data = NULL;
    size_t length = 0;
    int status;

    command[0] = type;
    command[1] = "getattr";
    command[2] = "keytab";
    command[3] = name;
    command[4] = "sync";
    command[5] = NULL;
    status = run_command(r, command, &data, &length);
    if (status != 0)
        return 0;
    if (data == NULL || strstr(data, "kaserver\n") == NULL) {
        command[1] = "setattr";
        command[5] = "kaserver";
        command[6] = NULL;
        status = run_command(r, command, NULL, NULL);
        if (status != 0)
            return 0;
    }
    return 1;
}


/*
**  Given a remctl object, the Kerberos context, the name of a keytab object,
**  and a file name, call the correct wallet commands to download a keytab and
**  write it to that file.  Returns the setatus or 255 on an internal error.
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

    if (srvtab != NULL)
        if (!set_sync(r, type, name))
            return 255;
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
