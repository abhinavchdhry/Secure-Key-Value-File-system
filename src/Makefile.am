bin_PROGRAMS = kvfs
kvfs_SOURCES = kvfs.c log.c log.h  kvfs.h
AM_CFLAGS = @FUSE_CFLAGS@
LDADD = @FUSE_LIBS@ -lcrypto -lssl
