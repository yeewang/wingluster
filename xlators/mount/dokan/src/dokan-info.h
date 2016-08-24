#ifndef _GF_DOKAN_INFO_H_
#define _GF_DOKAN_INFO_H_

typedef struct
{
        const char* path;
        struct FUSE_STAT* stbuf;
} dokan_getattr_t;

typedef struct
{
        const char* path;
        char* buf;
        size_t size;
} dokan_readlink_t;

typedef struct
{
        const char* path;
        mode_t mode;
        dev_t rdev;
} dokan_mknod_t;

typedef struct
{
        const char* path;
        mode_t mode;
} dokan_mkdir_t;

typedef struct
{
        const char* path;
} dokan_unlink_t;

typedef struct
{
        const char* path;
} dokan_rmdir_t;

typedef struct
{
        const char* from;
        const char* to;
} dokan_symlink_t;

typedef struct
{
        const char* from;
        const char* to;
} dokan_rename_t;

typedef struct
{
        const char* from;
        const char* to;
} dokan_link_t;

typedef struct
{
        const char* path;
        char* buf;
        size_t size;
        off_t offset;
        struct fuse_file_info* fi;
} dokan_read_t;

typedef struct
{
        const char* path;
        const char* buf;
        size_t size;
        off_t offset;
        struct fuse_file_info* fi;
} dokan_write_t;

typedef struct
{
        const char* path;
        struct fuse_file_info* fi;
} dokan_open_t, dokan_flush_t, dokan_release_t, dokan_opendir_t, dokan_releasedir_t;

typedef struct
{
        const char* path;
        void* buf;
        fuse_fill_dir_t filler;
        off_t offset;
        struct fuse_file_info* fi;

        char* out_buf;
        size_t out_size;
} dokan_readdirp_t;

typedef struct
{
        const char* path;
        int isdatasync;
        struct fuse_file_info* fi;
} dokan_fsync_t;

typedef struct
{
        const char* path;
        int mask;
} dokan_access_t;

typedef struct
{
        const char* path;
        struct statvfs* stbuf;
} dokan_statfs_t;

typedef struct
{
        const char* path;
        const char* name;
        const char* value;
        size_t size;
        int flags;
} dokan_setxattr_t;

typedef struct
{
        const char* path;
        const char* name;
        char* value;
        size_t size;
} dokan_getxattr_t;

typedef struct
{
        const char* path;
        const char* name;
} dokan_removexattr_t;

typedef struct
{
        const char* path;
        char* list;
        size_t size;
} dokan_listxattr_t;



#endif /* _GF_DOKAN_INFO_H_ */

