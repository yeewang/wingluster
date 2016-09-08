#ifndef _GF_DOKAN_INFO_H_
#define _GF_DOKAN_INFO_H_

#include <fuse.h>
#include "fuse-bridge.h"

typedef struct
{
        struct fuse_conn_info* conn;
} dokan_init_t;

typedef struct
{
        const char* path;
        struct FUSE_STAT* stbuf;
        struct fuse_file_info* fi;
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
        char* path;
        struct fuse_file_info* fi;
} dokan_open_t, dokan_flush_t, dokan_release_t, dokan_opendir_t,
  dokan_releasedir_t;

typedef struct
{
        const char *path;
        mode_t mode;
        struct fuse_file_info * fi;
} dokan_create_t;

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
} dokan_fsync_t, dokan_fsyncdir_t;

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

typedef struct
{
        uint64_t nodeid;
} dokan_lookup_dir_t;

typedef struct dokan_msg dokan_msg_t;
typedef struct
{
        dokan_msg_t* msg;
} dokan_autorelease_t, dokan_waitmsg_t;

typedef struct
{
        xlator_t* this;
        ino_t parent;
        const char* basename;
} dokan_lookup_t;

typedef struct
{
        const char *path;
        FUSE_OFF_T size;
} dokan_truncate_t;

typedef struct
{
        const char *path;
        FUSE_OFF_T size;
        struct fuse_file_info *fi;
} dokan_ftruncate_t;


typedef struct
{
        const char *path;
        int valid;

        struct timespec ts[2];

        mode_t mode;

        uid_t uid;
        gid_t gid;
} dokan_setattr_t;

typedef struct
{
        const char *path;
        struct fuse_file_info *fi;
        struct fuse_file_lock lk;
} dokan_setlk_t;

int
dokan_lookup_dir(uint64_t nodeid);

void
dokan_lookup(xlator_t* this, ino_t parent, char* bname);

void* dokan_mount_proc(void* data);


struct mount_data
{
        struct fuse_private* private;
        const char* mountpoint;
        char* fsname;
        unsigned long mountflags;
        char* mnt_param;
        int status_fd;
};

int dokan_send_result(xlator_t* this, dokan_msg_t* msg, int ret);
int dokan_send_err(xlator_t* this, dokan_msg_t* msg, int error);
dokan_msg_t* dokan_get_req(int type, size_t size);
void dokan_send_req(dokan_msg_t* msg);
void dokan_abort_req(dokan_msg_t* msg);
int dokan_get_result(dokan_msg_t* msg);
int dokan_get_result_and_cleanup(dokan_msg_t* msg);
void dokan_cleanup_req(dokan_msg_t* msg);

void
dokan_perform_lookup(xlator_t *this, char *path, inode_table_t *itable);


#endif /* _GF_DOKAN_INFO_H_ */

