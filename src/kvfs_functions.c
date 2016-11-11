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

struct entry {
	char *key;
	char *inodefile;
};

#define MAXFILECOUNT	(65536)

struct entry inodemap[MAXFILECOUNT];

int searchKey(char *key)
{
	int i;
	for (i = 0; i < MAXFILECOUNT; i++)
	{
		if (strcmp(inodemap[i].key, key) == 0)
			return i;
	}

	return (-1);
}

int firstInvalidEntry()
{
	int i;
	for (i = 0; i < MAXFILECOUNT; i++)
	{
		if (inodemap[i].inodefile == NULL)
			return i;
	}

	return (-1);	// Map full
}

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
int kvfs_getattr_impl(const char *path, struct stat *statbuf)
{
    return -1;
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
int kvfs_readlink_impl(const char *path, char *link, size_t size)
{
    return -1;
}

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?
int kvfs_mknod_impl(const char *path, mode_t mode, dev_t dev)
{
    return -1;
}

/** Create a directory */
int kvfs_mkdir_impl(const char *path, mode_t mode)
{
    return -1;
}

/** Remove a file */
int kvfs_unlink_impl(const char *path)
{
    return -1;
}

/** Remove a directory */
int kvfs_rmdir_impl(const char *path)
{
    return -1;
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int kvfs_symlink_impl(const char *path, const char *link)
{
    return -1;
}

/** Rename a file */
// both path and newpath are fs-relative
int kvfs_rename_impl(const char *path, const char *newpath)
{
    return -1;
}

/** Create a hard link to a file */
int kvfs_link_impl(const char *path, const char *newpath)
{
    return -1;
}

/** Change the permission bits of a file */
int kvfs_chmod_impl(const char *path, mode_t mode)
{
    return -1;
}

/** Change the owner and group of a file */
int kvfs_chown_impl(const char *path, uid_t uid, gid_t gid)
{
    return -1;
}

/** Change the size of a file */
int kvfs_truncate_impl(const char *path, off_t newsize)
{
    return -1;
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
int kvfs_utime_impl(const char *path, struct utimbuf *ubuf)
{
    return -1;
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
int kvfs_open_impl(const char *path, struct fuse_file_info *fi)
{
    return -1;
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
int kvfs_read_impl(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int i;

	if ((i = searchKey(path)) != -1)
	{
		
	}
	else	// File not present
	{
		// Create inodefile	
		char inodefilename[54];
		strcpy(inodefilename, key);
		int fd = open(strcat(inodefilename, ".inodefile"), O_RDWR);

		if (fd == -1)
		{
			printf("Failed to create .inodefile!\n");
			return -1;
		}
	}

    return -1;
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
int kvfs_write_impl(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
    return -1;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int kvfs_statfs_impl(const char *path, struct statvfs *statv)
{
    return -1;
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
// this is a no-op in BBFS.  It just logs the call and returns success
int kvfs_flush_impl(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nkvfs_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);
	
    return 0;
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
int kvfs_release_impl(const char *path, struct fuse_file_info *fi)
{
    return -1;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int kvfs_fsync_impl(const char *path, int datasync, struct fuse_file_info *fi)
{
    return -1;
}

#ifdef HAVE_SYS_XATTR_H
/** Set extended attributes */
int kvfs_setxattr_impl(const char *path, const char *name, const char *value, size_t size, int flags)
{
    return -1;
}

/** Get extended attributes */
int kvfs_getxattr_impl(const char *path, const char *name, char *value, size_t size)
{
    return -1;
}

/** List extended attributes */
int kvfs_listxattr_impl(const char *path, char *list, size_t size)
{
    return -1;
}

/** Remove extended attributes */
int kvfs_removexattr_impl(const char *path, const char *name)
{
    return -1;
}
#endif

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int kvfs_opendir_impl(const char *path, struct fuse_file_info *fi)
{
    return -1;
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

int kvfs_readdir_impl(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi)
{
    return -1;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int kvfs_releasedir_impl(const char *path, struct fuse_file_info *fi)
{
    return -1;
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
int kvfs_fsyncdir_impl(const char *path, int datasync, struct fuse_file_info *fi)
{
    return -1;
}

int kvfs_access_impl(const char *path, int mask)
{
    return -1;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
// Not implemented.  I had a version that used creat() to create and
// open the file, which it turned out opened the file write-only.

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
int kvfs_ftruncate_impl(const char *path, off_t offset, struct fuse_file_info *fi)
{
    return -1;
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
int kvfs_fgetattr_impl(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
    return -1;
}

