/*  $Id$
**
**  File handling for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007 Board of Trustees, Leland Stanford Jr. University
**
**  See README for licensing terms.
*/

#include <config.h>
#include <system.h>

#include <fcntl.h>

#include <client/internal.h>
#include <util/util.h>

/*
**  Given a filename, some data, and a length, write that data to the given
**  file safely and atomically by creating file.new, writing the data, linking
**  file to file.bak, and then renaming file.new to file.
*/
void
write_file(const char *name, const void *data, size_t length)
{
    int fd;
    ssize_t status;
    char *temp, *backup;

    temp = concat(name, ".new", (char *) 0);
    backup = concat(name, ".bak", (char *) 0);
    fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        sysdie("open of %s failed", temp);
    status = write(fd, data, length);
    if (status < 0)
        sysdie("write to %s failed", temp);
    else if (status != (ssize_t) length)
        die("write to %s truncated", temp);
    if (close(fd) < 0)
        sysdie("close of %s failed (file probably truncated)", temp);
    if (access(name, F_OK) == 0)
        if (link(name, backup) < 0)
            sysdie("link of %s to %s failed", name, backup);
    if (rename(temp, name) < 0)
        sysdie("rename of %s to %s failed", temp, name);
    free(temp);
    free(backup);
}
