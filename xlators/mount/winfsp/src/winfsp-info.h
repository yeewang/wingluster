#ifndef _GF_WINFSP_INFO_H_
#define _GF_WINFSP_INFO_H_

#include <fuse.h>
#include "fuse-bridge.h"

typedef struct
{
        struct fuse_conn_info* conn;
} winfsp_init_t;

typedef struct
{
        const char* path;
        struct FUSE_STAT* stbuf;
        struct fuse_file_info* fi;
} winfsp_getattr_t;

typedef struct
{
        const char* path;
        char* buf;
        size_t size;
} winfsp_readlink_t;

typedef struct
{
        const char* path;
        mode_t mode;
        dev_t rdev;
} winfsp_mknod_t;

typedef struct
{
        const char* path;
        mode_t mode;
} winfsp_mkdir_t;

typedef struct
{
        const char* path;
} winfsp_unlink_t;

typedef struct
{
        const char* path;
} winfsp_rmdir_t;

typedef struct
{
        const char* from;
        const char* to;
} winfsp_symlink_t;

typedef struct
{
        const char* from;
        const char* to;
} winfsp_rename_t;

typedef struct
{
        const char* from;
        const char* to;
} winfsp_link_t;

typedef struct
{
        const char* path;
        char* buf;
        size_t size;
        off_t offset;
        struct fuse_file_info* fi;
} winfsp_read_t;

typedef struct
{
        const char* path;
        const char* buf;
        size_t size;
        off_t offset;
        struct fuse_file_info* fi;
} winfsp_write_t;

typedef struct
{
        char* path;
        struct fuse_file_info* fi;
} winfsp_open_t, winfsp_flush_t, winfsp_release_t, winfsp_opendir_t,
  winfsp_releasedir_t;

typedef struct
{
        const char *path;
        mode_t mode;
        struct fuse_file_info * fi;
} winfsp_create_t;

typedef struct
{
        struct list_head list;
        size_t off;
        size_t size;
} winfsp_readdirp_item_t;

typedef struct
{
        const char* path;
        void* buf;
        fuse_fill_dir_t filler;
        off_t offset;
        struct fuse_file_info* fi;

        pthread_cond_t  cond;
        pthread_mutex_t mutex;
        struct list_head list;

        char* out_buf;
        size_t out_size;
} winfsp_readdirp_t;

typedef struct
{
        const char* path;
        int isdatasync;
        struct fuse_file_info* fi;
} winfsp_fsync_t, winfsp_fsyncdir_t;

typedef struct
{
        const char* path;
        int mask;
} winfsp_access_t;

typedef struct
{
        const char* path;
        struct statvfs* stbuf;
} winfsp_statfs_t;

typedef struct
{
        const char* path;
        const char* name;
        const char* value;
        size_t size;
        int flags;
} winfsp_setxattr_t;

typedef struct
{
        const char* path;
        const char* name;
        char* value;
        size_t size;
} winfsp_getxattr_t;

typedef struct
{
        const char* path;
        const char* name;
} winfsp_removexattr_t;

typedef struct
{
        const char* path;
        char* list;
        size_t size;
} winfsp_listxattr_t;

typedef struct
{
        uint64_t nodeid;
} winfsp_lookup_dir_t;

typedef struct winfsp_msg winfsp_msg_t;
typedef struct
{
        winfsp_msg_t* msg;
} winfsp_autorelease_t, winfsp_waitmsg_t;

typedef struct
{
        xlator_t* this;
        ino_t parent;
        const char* basename;
} winfsp_lookup_t;

typedef struct
{
        ino_t nodeid;
        uint64_t nlookup;
} winfsp_forget_t;

typedef struct
{
        size_t count;
        winfsp_forget_t items[];
} winfsp_batch_forget_t;

typedef struct
{
        const char *path;
        off_t size;
        struct fuse_file_info *fi;
} winfsp_fallocate_t;

typedef struct
{
        const char *path;
        int valid;

        struct timespec ts[2];

        mode_t mode;

        uid_t uid;
        gid_t gid;

        off_t off;

        struct fuse_file_info *fi;
} winfsp_setattr_t;

typedef struct
{
        const char *path;
        struct fuse_file_info *fi;
        struct fuse_file_lock lk;
} winfsp_setlk_t;

typedef struct
{
        struct list_head children;
        char parent[250];
} winfsp_directory_node;

int
winfsp_lookup_dir(uint64_t nodeid);

void
winfsp_lookup(xlator_t* this, ino_t parent, char* bname);

void* winfsp_mount_proc(void* data);


struct mount_data
{
        struct fuse_private* private;
        const char* mountpoint;
        char* fsname;
        unsigned long mountflags;
        char* mnt_param;
        int status_fd;
};

int winfsp_send_result(xlator_t* this, winfsp_msg_t* msg, int ret);
int winfsp_send_err(xlator_t* this, winfsp_msg_t* msg, int error);
winfsp_msg_t* winfsp_get_req(int type, size_t size);
void winfsp_send_req(winfsp_msg_t* msg);
void winfsp_abort_req(winfsp_msg_t* msg);
int winfsp_get_result(winfsp_msg_t* msg);
int winfsp_get_result_and_cleanup(winfsp_msg_t* msg);
void winfsp_cleanup_req(winfsp_msg_t* msg);

void
winfsp_perform_lookup(xlator_t *this, char *path, inode_table_t *itable);


#endif /* _GF_WINFSP_INFO_H_ */

