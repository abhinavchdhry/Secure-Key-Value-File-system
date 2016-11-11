/*
  Key Value System
  Copyright (C) 2016 Hung-Wei Tseng, Ph.D. <hungwei_tseng@ncsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  This code is derived from function prototypes found /usr/include/fuse/fuse.h
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  His code is licensed under the LGPLv2.
  A copy of that code is included in the file fuse.h
  
  The point of this FUSE filesystem is to provide an introduction to
  FUSE.  It was my first FUSE filesystem as I got to know the
  software; hopefully, the comments in this code will help people who
  follow later to get a gentler introduction.

*/

#include "kvfs.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#include "log.h"

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/md5.h>
#endif

char *str2md5(const char *str, int length) {
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char*)malloc(33);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return out;
}

#include "kvfs_functions.c"

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int kvfs_getattr(const char *path, struct stat *statbuf)
{
//    log_msg("    kvfs_fullpath:  path = \"%s\"\n",path);
    return kvfs_getattr_impl(str2md5(path, strlen(path)), statbuf);
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
// Note the system readlink() will truncate and lose the terminating
// null.  So, the size passed to to the system readlink() must be one
// less than the size passed to kvfs_readlink()
// kvfs_readlink() code by Bernardo F Costa (thanks!)
int kvfs_readlink(const char *path, char *link, size_t size)
{
    return kvfs_readlink_impl(str2md5(path, strlen(path)), link, size);
}

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?
int kvfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    return kvfs_mknod_impl(str2md5(path, strlen(path)), mode, dev);
}

/** Create a directory */
int kvfs_mkdir(const char *path, mode_t mode)
{
    return kvfs_mkdir_impl(str2md5(path, strlen(path)), mode);
}

/** Remove a file */
int kvfs_unlink(const char *path)
{
    return kvfs_unlink_impl(str2md5(path, strlen(path)));
}

/** Remove a directory */
int kvfs_rmdir(const char *path)
{
    return kvfs_rmdir_impl(str2md5(path, strlen(path)));
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int kvfs_symlink(const char *path, const char *link)
{
    return kvfs_symlink_impl(str2md5(path, strlen(path)),str2md5(link, strlen(link)));
}

/** Rename a file */
// both path and newpath are fs-relative
int kvfs_rename(const char *path, const char *newpath)
{
    return kvfs_rename_impl(str2md5(path, strlen(path)),str2md5(newpath, strlen(newpath)));
}

/** Create a hard link to a file */
int kvfs_link(const char *path, const char *newpath)
{
    return kvfs_link_impl(str2md5(path, strlen(path)),str2md5(newpath, strlen(newpath)));
}

/** Change the permission bits of a file */
int kvfs_chmod(const char *path, mode_t mode)
{
    return kvfs_chmod_impl(str2md5(path, strlen(path)), mode);
}

/** Change the owner and group of a file */
int kvfs_chown(const char *path, uid_t uid, gid_t gid)
{
    return kvfs_chown_impl(str2md5(path, strlen(path)), uid, gid);
}

/** Change the size of a file */
int kvfs_truncate(const char *path, off_t newsize)
{
    return kvfs_truncate_impl(str2md5(path, strlen(path)), newsize);
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
int kvfs_utime(const char *path, struct utimbuf *ubuf)
{
    return kvfs_utime_impl(str2md5(path, strlen(path)), ubuf);
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */
int kvfs_open(const char *path, struct fuse_file_info *fi)
{
    return kvfs_open_impl(str2md5(path, strlen(path)), fi);
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.
int kvfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    return kvfs_read_impl(str2md5(path, strlen(path)), buf, size, offset, fi);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
// As  with read(), the documentation above is inconsistent with the
// documentation for the write() system call.
int kvfs_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
    return kvfs_write_impl(str2md5(path, strlen(path)), buf, size, offset, fi);
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int kvfs_statfs(const char *path, struct statvfs *statv)
{
    return kvfs_statfs_impl(str2md5(path, strlen(path)), statv);
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
// this is a no-op in KVFS.  It just logs the call and returns success
int kvfs_flush(const char *path, struct fuse_file_info *fi)
{
    return kvfs_flush_impl(str2md5(path, strlen(path)), fi);
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int kvfs_release(const char *path, struct fuse_file_info *fi)
{
    return kvfs_release_impl(str2md5(path, strlen(path)), fi);
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int kvfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    return kvfs_fsync_impl(str2md5(path, strlen(path)), datasync, fi);
}

#ifdef HAVE_SYS_XATTR_H
/** Set extended attributes */
int kvfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    return kvfs_setxattr_impl(str2md5(path, strlen(path)), name, size, flag);
}

/** Get extended attributes */
int kvfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    return kvfs_getxattr_impl(str2md5(path, strlen(path)), name, size, flag);
}

/** List extended attributes */
int kvfs_listxattr(const char *path, char *list, size_t size)
{
    return kvfs_listxattr_impl(str2md5(path, strlen(path)), list, size);
}

/** Remove extended attributes */
int kvfs_removexattr(const char *path, const char *name)
{
    return kvfs_removexattr_impl(str2md5(path, strlen(path)), name);
}
#endif

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int kvfs_opendir(const char *path, struct fuse_file_info *fi)
{
    return kvfs_opendir_impl(str2md5(path, strlen(path)), fi);
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */

int kvfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi)
{
    return kvfs_readdir_impl(str2md5(path, strlen(path)), buf, filler, offset, fi);
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int kvfs_releasedir(const char *path, struct fuse_file_info *fi)
{
    return kvfs_releasedir_impl(str2md5(path, strlen(path)), fi);
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
// when exactly is this called?  when a user calls fsync and it
// happens to be a directory? ??? >>> I need to implement this...
int kvfs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    return kvfs_fsyncdir_impl(str2md5(path, strlen(path)), datasync, fi);
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *kvfs_init(struct fuse_conn_info *conn)
{
    log_msg("\nkvfs_init()\n");
    
    log_conn(conn);
    log_fuse_context(fuse_get_context());
    
    return KVFS_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void kvfs_destroy(void *userdata)
{
    log_msg("\nkvfs_destroy(userdata=0x%08x)\n", userdata);
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int kvfs_access(const char *path, int mask)
{
    log_msg("    kvfs_fullpath:  path = \"%s\"\n",path);
    return kvfs_access_impl(str2md5(path, strlen(path)), mask);
}

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
int kvfs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
    return kvfs_ftruncate_impl(str2md5(path, strlen(path)), offset, fi);
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
int kvfs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
    return kvfs_fgetattr_impl(str2md5(path, strlen(path)), statbuf, fi);
}

struct fuse_operations kvfs_oper = {
  .getattr = kvfs_getattr,
  .readlink = kvfs_readlink,
  // no .getdir -- that's deprecated
  .getdir = NULL,
  .mknod = kvfs_mknod,
  .mkdir = kvfs_mkdir,
  .unlink = kvfs_unlink,
  .rmdir = kvfs_rmdir,
  .symlink = kvfs_symlink,
  .rename = kvfs_rename,
  .link = kvfs_link,
  .chmod = kvfs_chmod,
  .chown = kvfs_chown,
  .truncate = kvfs_truncate,
  .utime = kvfs_utime,
  .open = kvfs_open,
  .read = kvfs_read,
  .write = kvfs_write,
  /** Just a placeholder, don't set */ // huh???
  .statfs = kvfs_statfs,
  .flush = kvfs_flush,
  .release = kvfs_release,
  .fsync = kvfs_fsync,
  
#ifdef HAVE_SYS_XATTR_H
  .setxattr = kvfs_setxattr,
  .getxattr = kvfs_getxattr,
  .listxattr = kvfs_listxattr,
  .removexattr = kvfs_removexattr,
#endif
  
  .opendir = kvfs_opendir,
  .readdir = kvfs_readdir,
  .releasedir = kvfs_releasedir,
  .fsyncdir = kvfs_fsyncdir,
  .init = kvfs_init,
  .destroy = kvfs_destroy,
  .access = kvfs_access,
  .ftruncate = kvfs_ftruncate,
  .fgetattr = kvfs_fgetattr
};

void kvfs_usage()
{
    fprintf(stderr, "usage:  kvfs [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main(int argc, char *argv[])
{
    int fuse_stat;
    struct kvfs_state *kvfs_data;

    // kvfs doesn't do any access checking on its own (the comment
    // blocks in fuse.h mention some of the functions that need
    // accesses checked -- but note there are other functions, like
    // chown(), that also need checking!).  Since running kvfs as root
    // will therefore open Metrodome-sized holes in the system
    // security, we'll check if root is trying to mount the filesystem
    // and refuse if it is.  The somewhat smaller hole of an ordinary
    // user doing it with the allow_other flag is still there because
    // I don't want to parse the options string.
    if ((getuid() == 0) || (geteuid() == 0)) {
	fprintf(stderr, "Running KVFS as root opens unnacceptable security holes\n");
	return 1;
    }

    // See which version of fuse we're running
    fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);
    
    // Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs)
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
	kvfs_usage();

    kvfs_data = malloc(sizeof(struct kvfs_state));
    if (kvfs_data == NULL) {
	perror("main calloc");
	abort();
    }

    // Pull the rootdir out of the argument list and save it in my
    // internal data
    kvfs_data->rootdir = realpath(argv[argc-2], NULL);
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
    
    kvfs_data->logfile = log_open();
    
    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &kvfs_oper, kvfs_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
    
    return fuse_stat;
}
