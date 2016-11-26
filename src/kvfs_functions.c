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

	Authors: Abhinav Choudhury (200159347), Aditya Virmani	

*/

#include "kvfs.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <wordexp.h>

/* 
++++++++++++++++++++++++++++++++++++++++++++++++++++++
				FILE SYSTEM ARCHITECTURE
++++++++++++++++++++++++++++++++++++++++++++++++++++++

Our experimental file system is built on top of the existing Linux filesystem and uses *linux files as metadata objects*
There is no concept of a directory and hence related functions are just dummy functions.

The medatadata for every physical file in our *virtual* (and extremely low-performace) file system is kept in an *inodefile*,
which is just a physical linux file on disk with the .inodefile file extension. This contains all the metadata for the actual file
as raw text in the following order:
<filetype=0,1> | <protection information> | <size of file> | <last access time> | <last mod. time> | <owner ID> | <physical location filename>

The <physical location filename> is the name of another physical linux file that contains the actual data for our file.

Our filesystem keeps an in-memory map of keys to *inodefile* filename mapping. This is done to improve perfomace a little by reducing file access overhead on lookups.

*/

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/md5.h>
#endif

char *str2md5_local(const char *str, int length) {
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

int tempDirInited = 0;
void checkAndInitTempDir()
{
	if (!tempDirInited)
	{
	       wordexp_t p;
	        wordexp("~", &p, 0);

        	char fullPath[200];
        	strcpy(fullPath, p.we_wordv[0]);
		strcat(fullPath, "/.tmpfs");

		if (mkdir(fullPath, 0700) < 0) 
		{
			if (errno == EEXIST)
			{
				// Recursively delete the folder first
				DIR *theFolder = opendir(fullPath);
			    struct dirent *next_file;
			    char filepath[500];

			    while ( (next_file = readdir(theFolder)) != NULL )
			    {
			        // build the path for each file in the folder
    				   sprintf(filepath, "%s/%s", fullPath, next_file->d_name);
			        int r = remove(filepath);
				if (r < 0)
					log_msg("REMOVE failed filepath = %s, errno = %d\n", filepath, errno);
			    }
			    closedir(theFolder);
				if (rmdir(fullPath) < 0)
				{
					log_msg("RMdir failed! errno = %d\n", errno);
				}
				else if (mkdir(fullPath, 0700) < 0)
				{
					log_msg("MKDIR Failed again! errno = %d\n", errno);
				}
				tempDirInited = 1;
			}
			else
			{
				log_msg("Failed to create tmpfs directory! errno = %d\n", errno);
			}
		}
		else
			tempDirInited = 1;
	}
}

struct entry {
	char *key;
	char *inodefile;
};

#define MAXFILECOUNT	(256)

struct entry inodemap[MAXFILECOUNT];

int searchKey(char *key)
{
	int i;
log_msg("Inside searchKey key = %s\n", key);
	for (i = 0; i < MAXFILECOUNT; i++)
	{
//		log_msg("i = %d\n", i);
		if (inodemap[i].key != NULL && strcmp(inodemap[i].key, key) == 0)
		{
//			log_msg("Found key = %s, returning\n", key);
			return i;
		}
		else
		{
//			log_msg("Not key i = %d\n", i);
		}
	}

	log_msg("Not found!\n");
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

struct metadata {
	int 				filetype;			// Type of file
	int 				protection;			// Protection/access information
	long unsigned int	 	size;				// Size
	struct timeval 			lastAccessTime;		// Last access time
	struct timeval 			lastModTime;		// Last modification time
	int 				ownerId;			// ID of owner
	int				filenamelen;
	char 				contentFile[100];	// Filename of the contents file
};

#define CHECK(x)	do { \
		if (x < 0)	\
		{		\
			log_msg("Metadata read/write error!\n");	\
		}	\
	}	\
	while (0);	\

// Metadata read/write helper functions
int readMetadata(int fd, struct metadata* st)
{
	if (fd < 0 || st == NULL)
		return -1;

	CHECK(read(fd, &(st->filetype), sizeof(st->filetype)));
	CHECK(read(fd, &(st->protection), sizeof(st->protection)));
	CHECK(read(fd, &(st->size), sizeof(st->size)));
	CHECK(read(fd, &(st->lastAccessTime), sizeof(st->lastAccessTime)));
	CHECK(read(fd, &(st->lastModTime), sizeof(st->lastModTime)));
	CHECK(read(fd, &(st->ownerId), sizeof(st->ownerId)));
	CHECK(read(fd, &(st->filenamelen), sizeof(st->filenamelen)));
	CHECK(read(fd, st->contentFile, st->filenamelen));
	st->contentFile[st->filenamelen] = '\0';

	return 0;
}

int writeMetadata(int fd, struct metadata* st)
{
	if (fd < 0 || st == NULL)
		return -1;

	CHECK(write(fd, &(st->filetype), sizeof(st->filetype)));
	CHECK(write(fd, &(st->protection), sizeof(st->protection)));
	CHECK(write(fd, &(st->size), sizeof(st->size)));
	CHECK(write(fd, &(st->lastAccessTime), sizeof(st->lastAccessTime)));
	CHECK(write(fd, &(st->lastModTime), sizeof(st->lastModTime)));
	CHECK(write(fd, &(st->ownerId), sizeof(st->ownerId)));
	CHECK(write(fd, &(st->filenamelen), sizeof(st->filenamelen)));
	CHECK(write(fd, st->contentFile, st->filenamelen));

	return 0;
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
log_msg("\n%s: path = %s\n", __FUNCTION__, path);
	
	char *rootkey = str2md5_local("/", strlen("/"));
	wordexp_t p;
	wordexp("~", &p, 0);
	
	char fullPath[200];
	strcpy(fullPath, p.we_wordv[0]);
	strcat(fullPath, "/.tmpfs/");
	strcat(fullPath, path);

	checkAndInitTempDir();
	
	if (strcmp(path, rootkey) == 0)
	{
		int ret = open(fullPath, O_RDONLY);
		if (ret < 0 && errno == ENOENT)
		{
			int ret1 = open(fullPath, O_RDWR | O_CREAT, 0700);
			if (ret1 < 0)
			{
				log_msg("%s: Falied to create file for root! errno = %d\n", __FUNCTION__, errno);
			}
			else
			{
				close(ret1);
				log_msg("%s: Created file entry for root node!\n", __FUNCTION__);
			}
		}
		else
		{
			close(ret);
		}
	}

	int r = kvfs_open_impl(path, NULL);

	r = stat(fullPath, statbuf);
        if (strcmp(path, rootkey) == 0)
             statbuf->st_mode = S_IFDIR | 0755;

	return r;
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
log_msg("\n%s\n", __FUNCTION__);
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
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Create a directory */
int kvfs_mkdir_impl(const char *path, mode_t mode)
{
log_msg("\n%s\n", __FUNCTION__);
//    return -1;
	int res;



	res = mkdir(path, mode);

	if (res == -1)

		return -errno;



	return 0;
}

/** Remove a file */
int kvfs_unlink_impl(const char *path)
{
log_msg("\n%s\n", __FUNCTION__);
    wordexp_t p;
    wordexp("~", &p, 0);

    char fullPath[200];
    strcpy(fullPath, p.we_wordv[0]);
    strcat(fullPath, "/.tmpfs/");
	strcat(fullPath, path);

	return unlink(fullPath);
}

/** Remove a directory */
int kvfs_rmdir_impl(const char *path)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int kvfs_symlink_impl(const char *path, const char *link)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Rename a file */
// both path and newpath are fs-relative
int kvfs_rename_impl(const char *path, const char *newpath)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Create a hard link to a file */
int kvfs_link_impl(const char *path, const char *newpath)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Change the permission bits of a file */
int kvfs_chmod_impl(const char *path, mode_t mode)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Change the owner and group of a file */
int kvfs_chown_impl(const char *path, uid_t uid, gid_t gid)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Change the size of a file */
int kvfs_truncate_impl(const char *path, off_t newsize)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
int kvfs_utime_impl(const char *path, struct utimbuf *ubuf)
{
log_msg("\n%s\n", __FUNCTION__);
	wordexp_t p;
        wordexp("~", &p, 0);

        char fullPath[200];
        strcpy(fullPath, p.we_wordv[0]);
        strcat(fullPath, "/.tmpfs/");
	strcat(fullPath, path);

	return utime(fullPath, ubuf);
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
       wordexp_t p;
        wordexp("~", &p, 0);

        char fullPath[200];
        strcpy(fullPath, p.we_wordv[0]);
	strcat(fullPath, "/.tmpfs/");
	strcat(fullPath, path);
log_msg("open_impl, fullpath - %s\n", fullPath);
	
	int ret = open(fullPath, O_RDONLY);
	if (ret < 0 && errno == ENOENT)
	{
		int ret1 = open(fullPath, O_RDWR | O_CREAT, 0700);
		if (ret1 < 0)
		{
			log_msg("%s: Failed to create file, path = %s! errno = %d\n", __FUNCTION__, fullPath, errno);
		}
		else close(ret1);
	}
	else if (ret < 0)
	{
		log_msg("%s: open_impl failed for some reason!\n", __FUNCTION__);
	}
	else if (ret >= 0)
	{
		log_msg("%s: open_impl succeeds!\n", __FUNCTION__);
		close(ret);
	}

	return 0;
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
	       wordexp_t p;
        wordexp("~", &p, 0);

        char fullPath[200];
        strcpy(fullPath, p.we_wordv[0]);
	strcat(fullPath, "/.tmpfs/");
        strcat(fullPath, path);
log_msg("read_impl\n");
        int ret = open(fullPath, O_RDONLY);
	if (ret < 0)
	{
		errno = ENOENT;	// File not found
		log_msg("Open failed! errno = %d\n", errno);
		return -1;
	}
	
	lseek(ret, offset, SEEK_CUR);

	int count = read(ret, buf, size);
	close(ret);

	return count;
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
        wordexp_t p;
        wordexp("~", &p, 0);

        char fullPath[200];
        strcpy(fullPath, p.we_wordv[0]);
	strcat(fullPath, "/.tmpfs/");
        strcat(fullPath, path);

        int ret = open(fullPath, O_RDWR);
	if (ret < 0)
	{
		errno = ENOENT;
		log_msg("Open failed! errno = %d\n", errno);
		return -1;
	}
	
	lseek(ret, offset, SEEK_CUR);

	int bytes = write(ret, buf, size);
	close(ret);

	return bytes;
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
    log_msg("\n%s\n", __FUNCTION__);
    struct statvfs tmp;
    int res = statvfs("/etc/",&tmp);
    *statv = tmp;
    #ifdef kuch
    statv->f_bsize = 100;    /* Filesystem block size */
    statv->f_frsize = 100;   /* Fragment size */
    statv->f_blocks =100;   /* Size of fs in f_frsize units */
    statv->f_bfree = 100;    /* Number of free blocks */
    statv->f_bavail = 100;   /* Number of free blocks for unprivileged users */
    statv->f_files = 100;    /* Number of inodes */
    statv->f_ffree = 100;    /* Number of free inodes */
    statv->f_favail = 100;   /* Number of free inodes for unprivileged users */
    statv->f_fsid = 100;     /* Filesystem ID */
    statv->f_flag = 100;     /* Mount flags */
    statv->f_namemax = 100;  /* Maximum filename length */
    #endif
    return 0;
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
log_msg("\n%s\n", __FUNCTION__);
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
log_msg("\n%s\n", __FUNCTION__);
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
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

#ifdef HAVE_SYS_XATTR_H
/** Set extended attributes */
int kvfs_setxattr_impl(const char *path, const char *name, const char *value, size_t size, int flags)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Get extended attributes */
int kvfs_getxattr_impl(const char *path, const char *name, char *value, size_t size)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** List extended attributes */
int kvfs_listxattr_impl(const char *path, char *list, size_t size)
{
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

/** Remove extended attributes */
int kvfs_removexattr_impl(const char *path, const char *name)
{
log_msg("\n%s\n", __FUNCTION__);
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
       wordexp_t p;
        wordexp("~", &p, 0);

        char fullPath[200];
        strcpy(fullPath, p.we_wordv[0]);
        strcat(fullPath, "/.tmpfs/");
        strcat(fullPath, path);

log_msg("\n%s, path = %s\n", __FUNCTION__, path);
	if (opendir(fullPath) == NULL)
		log_msg("%s: returned NULL, errno = %d\n", __FUNCTION__, errno);
    return 0;
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
log_msg("\n%s\n", __FUNCTION__);
	int i;
	for (i = 0; i < MAXFILECOUNT; i++) {
		if (inodemap[i].key && inodemap[i].inodefile)
		{
			struct stat st;
			kvfs_getattr_impl(inodemap[i].key, &st);
			filler(buf, inodemap[i].key, &st, 0);
		}
	}

        wordexp_t p;
        wordexp("~", &p, 0);

        char fullPath[200];
        strcpy(fullPath, p.we_wordv[0]);
        strcat(fullPath, "/.tmpfs/");

	DIR *theFolder = opendir(fullPath);
	struct dirent *next_file;
	char filepath[256];

	while ( (next_file = readdir(theFolder)) != NULL )
	{
		// build the path for each file in the folder
		struct stat st;
		kvfs_getattr_impl(next_file->d_name, &st);
//		sprintf(filepath, "%s/%s", "path/of/folder", next_file->d_name);
//		remove(filepath);
		filler(buf, next_file->d_name, &st, 0);
	}
	closedir(theFolder);

    return 0;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int kvfs_releasedir_impl(const char *path, struct fuse_file_info *fi)
{
log_msg("\n%s\n", __FUNCTION__);
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
log_msg("\n%s\n", __FUNCTION__);
    return -1;
}

int kvfs_access_impl(const char *path, int mask)
{
log_msg("\n%s: path = %s\n", __FUNCTION__, path);
	int i;
//	if ((i = searchKey(path)) < 0)	// Entry does not exist. Create an entry by calling kvfs_open_impl
//	{
//		kvfs_open_impl(path, NULL);
//	}

	// TODO: Need to do permission checks here

    return 0;
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
log_msg("\n%s\n", __FUNCTION__);
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
    log_msg("\n%s: path = %s\n", __FUNCTION__, path);
    return -1;
}

