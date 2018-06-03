/*
 * File handling for the wallet client.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2007-2008, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * SPDX-License-Identifier: MIT
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <client/internal.h>
#include <util/messages.h>
#include <util/xmalloc.h>

/*
 * Given a filename, some data, and a length, write that data to the given
 * file safely, but overwrite any existing file by that name.
 */
void
overwrite_file(const char *name, const void *data, size_t length)
{
    int fd;
    ssize_t status;

    if (access(name, F_OK) == 0)
        if (unlink(name) < 0)
            sysdie("unable to delete existing file %s", name);
    fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        sysdie("open of %s failed", name);
    if (length > 0) {
        status = write(fd, data, length);
        if (status < 0)
            sysdie("write to %s failed", name);
        else if (status != (ssize_t) length)
            die("write to %s truncated", name);
    }
    if (close(fd) < 0)
        sysdie("close of %s failed (file probably truncated)", name);
}


/*
 * Given a filename, some data, and a length, append that data to an existing
 * file.  Dies on any failure.
 */
void
append_file(const char *name, const void *data, size_t length)
{
    int fd;
    ssize_t status;

    fd = open(name, O_WRONLY | O_APPEND);
    if (fd < 0)
        sysdie("open of %s failed", name);
    if (length > 0) {
        status = write(fd, data, length);
        if (status < 0)
            sysdie("write to %s failed", name);
        else if (status != (ssize_t) length)
            die("write to %s truncated", name);
    }
    if (close(fd) < 0)
        sysdie("close of %s failed (file probably truncated)", name);
}


/*
 * Given a filename, some data, and a length, write that data to the given
 * file safely and atomically by creating file.new, writing the data, linking
 * file to file.bak, and then renaming file.new to file.
 */
void
write_file(const char *name, const void *data, size_t length)
{
    char *temp, *backup;

    xasprintf(&temp, "%s.new", name);
    xasprintf(&backup, "%s.bak", name);
    overwrite_file(temp, data, length);
    if (access(name, F_OK) == 0) {
        if (access(backup, F_OK) == 0)
            if (unlink(backup) < 0)
                sysdie("unlink of old backup %s failed", backup);
        if (link(name, backup) < 0)
            sysdie("link of %s to %s failed", name, backup);
    }
    if (rename(temp, name) < 0)
        sysdie("rename of %s to %s failed", temp, name);
    free(temp);
    free(backup);
}


/*
 * Given a remctl object, the command prefix, object type, and object name,
 * and a file (which may be NULL), send a wallet get command and write the
 * results to the provided file.  If the file is NULL, write the results to
 * standard output instead.  Returns 0 on success and an exit status on
 * failure.
 */
int
get_file(struct remctl *r, const char *prefix, const char *type,
         const char *name, const char *file)
{
    const char *command[5];
    char *data = NULL;
    size_t length = 0;
    int status;

    command[0] = prefix;
    command[1] = "get";
    command[2] = type;
    command[3] = name;
    command[4] = NULL;
    status = run_command(r, command, &data, &length);
    if (status != 0)
        return status;

    /* The empty string is valid data. */
    if (data == NULL)
        length = 0;
    if (file != NULL)
        write_file(file, data, length);
    else if (length > 0) {
        if (fwrite(data, length, 1, stdout) != 1)
            sysdie("cannot write to standard output");
    }
    if (data != NULL)
        free(data);
    return 0;
}


/*
 * Read all of a file into memory and return the contents in newly allocated
 * memory.  Returns the size of the file contents in the second argument if
 * it's not NULL.  Handles a file name of "-" to mean standard input.  Dies on
 * any failure.
 */
void *
read_file(const char *name, size_t *length)
{
    char *contents;
    size_t size, offset;
    int fd;
    struct stat st;
    ssize_t status;

    if (strcmp(name, "-") == 0) {
        fd = fileno(stdin);
        size = BUFSIZ;
        contents = xmalloc(size);
    } else {
        fd = open(name, O_RDONLY);
        if (fd < 0)
            sysdie("cannot open file %s", name);
        if (fstat(fd, &st) < 0)
            sysdie("cannot stat file %s", name);
        size = st.st_size;
        contents = xmalloc(size);
    }
    offset = 0;
    do {
        if (offset >= size - 1) {
            size += BUFSIZ;
            contents = xrealloc(contents, size);
        }
        do {
            status = read(fd, contents + offset, size - offset - 1);
        } while (status == -1 && errno == EINTR);
        if (status < 0)
            sysdie("cannot read from file");
        offset += status;
    } while (status > 0);
    close(fd);
    if (length != NULL)
        *length = offset;
    return contents;
}
