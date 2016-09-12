/*
  Copyright 2016 StorSwift.com

  wangyi8848@gmail.com
*/

#include <sys/wait.h>
#include <fuse.h>
#include "fuse-bridge.h"
#include "mount-gluster-compat.h"
#include "glusterfs.h"
#include "byte-order.h"
#include "compat-errno.h"
#include "glusterfs-acl.h"
#include "dokan-info.h"


void
dokan_lookup(xlator_t* this, ino_t parent, char* bname)
{
        dokan_msg_t* msg = NULL;
        dokan_lookup_t* params = NULL;

        msg = dokan_get_req(FUSE_LOOKUP, sizeof(dokan_lookup_t));
        if (msg == NULL)
                return -1;

        msg->autorelease = _gf_true;

        params = (dokan_lookup_t*)msg->args;
        params->this = this;
        params->parent = parent;
        params->basename = gf_strdup(bname);

        dokan_send_req(msg);
}

static int
dokan_getattr(const char* path, struct FUSE_STAT* stbuf)
{
        dokan_msg_t* msg = NULL;
        dokan_getattr_t* params = NULL;

        msg = dokan_get_req(FUSE_GETATTR, sizeof(dokan_getattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_getattr_t*)msg->args;
        params->path = path;
        params->stbuf = stbuf;
        params->fi = NULL;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_fgetattr(const char *path, struct FUSE_STAT *stbuf,
        struct fuse_file_info *fi)
{
        dokan_msg_t* msg = NULL;
        dokan_getattr_t* params = NULL;

        msg = dokan_get_req(FUSE_GETATTR, sizeof(dokan_getattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_getattr_t*)msg->args;
        params->path = path;
        params->stbuf = stbuf;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_access(const char* path, int mask)
{
        dokan_msg_t* msg = NULL;
        dokan_access_t* params = NULL;

        msg = dokan_get_req(FUSE_ACCESS, sizeof(dokan_access_t));
        if (msg == NULL)
                return -1;

        params = (dokan_access_t*)msg->args;
        params->path = path;
        params->mask = mask;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_readlink(const char* path, char* buf, size_t size)
{
        dokan_msg_t* msg = NULL;
        dokan_readlink_t* params = NULL;

        msg = dokan_get_req(FUSE_READLINK, sizeof(dokan_readlink_t));
        if (msg == NULL)
                return -1;

        params = (dokan_readlink_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->size = size;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_mknod(const char* path, mode_t mode, dev_t rdev)
{
        dokan_msg_t* msg = NULL;
        dokan_mknod_t* params = NULL;

        msg = dokan_get_req(FUSE_MKNOD, sizeof(dokan_mknod_t));
        if (msg == NULL)
                return -1;

        params = (dokan_mknod_t*)msg->args;
        params->path = path;
        params->mode = mode;
        params->rdev = rdev;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_mkdir(const char* path, mode_t mode)
{
        dokan_msg_t* msg = NULL;
        dokan_mkdir_t* params = NULL;

        msg = dokan_get_req(FUSE_MKDIR, sizeof(dokan_mkdir_t));
        if (msg == NULL)
                return -1;

        params = (dokan_mkdir_t*)msg->args;
        params->path = path;
        params->mode = mode;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_unlink(const char* path)
{
        dokan_msg_t* msg = NULL;
        dokan_unlink_t* params = NULL;

        msg = dokan_get_req(FUSE_UNLINK, sizeof(dokan_unlink_t));
        if (msg == NULL)
                return -1;

        params = (dokan_unlink_t*)msg->args;
        params->path = path;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_rmdir(const char* path)
{
        dokan_msg_t* msg = NULL;
        dokan_rmdir_t* params = NULL;

        msg = dokan_get_req(FUSE_RMDIR, sizeof(dokan_rmdir_t));
        if (msg == NULL)
                return -1;

        params = (dokan_rmdir_t*)msg->args;
        params->path = path;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_symlink(const char* from, const char* to)
{
        dokan_msg_t* msg = NULL;
        dokan_symlink_t* params = NULL;

        msg = dokan_get_req(FUSE_RMDIR, sizeof(dokan_symlink_t));
        if (msg == NULL)
                return -1;

        params = (dokan_symlink_t*)msg->args;
        params->from = from;
        params->to = to;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_rename(const char* from, const char* to)
{
        dokan_msg_t* msg = NULL;
        dokan_rename_t* params = NULL;

        msg = dokan_get_req(FUSE_RENAME, sizeof(dokan_rename_t));
        if (msg == NULL)
                return -1;

        params = (dokan_rename_t*)msg->args;
        params->from = from;
        params->to = to;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_link(const char* from, const char* to)
{
        dokan_msg_t* msg = NULL;
        dokan_link_t* params = NULL;

        msg = dokan_get_req(FUSE_LINK, sizeof(dokan_link_t));
        if (msg == NULL)
                return -1;

        params = (dokan_link_t*)msg->args;
        params->from = from;
        params->to = to;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
        dokan_msg_t* msg = NULL;
        dokan_create_t* params = NULL;

        msg = dokan_get_req(FUSE_CREATE, sizeof(dokan_create_t));
        if (msg == NULL)
                return -1;

        params = (dokan_create_t*)msg->args;
        params->path = path;
        params->mode = mode;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);

}

static int
dokan_open(const char* path, struct fuse_file_info* fi)
{
        dokan_msg_t* msg = NULL;
        dokan_open_t* params = NULL;

        msg = dokan_get_req(FUSE_OPEN, sizeof(dokan_open_t));
        if (msg == NULL)
                return -1;

        params = (dokan_open_t*)msg->args;
        params->path = path;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_read(const char* path, char* buf, size_t size, off_t offset,
           struct fuse_file_info* fi)
{
        dokan_msg_t* msg = NULL;
        dokan_read_t* params = NULL;

        msg = dokan_get_req(FUSE_READ, sizeof(dokan_read_t));
        if (msg == NULL)
                return -1;

        params = (dokan_read_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->size = size;
        params->offset = offset;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_write(const char* path, const char* buf, size_t size, off_t offset,
            struct fuse_file_info* fi)
{
        xlator_t* this = get_fuse_xlator();
        dokan_msg_t* msg = NULL;
        dokan_write_t* params = NULL;
        size_t n = 0;
        size_t part = 0;
        int ret = -1;

        while (n < size)  {
                if ((size - n) > this->ctx->page_size)
                        part = this->ctx->page_size;
                else
                        part = size - n;

                msg = dokan_get_req(FUSE_WRITE, sizeof(dokan_write_t));
                if (msg == NULL)
                        return -1;

                params = (dokan_write_t*)msg->args;
                params->path = path;
                params->buf = buf + n;
                params->size = part;
                params->offset = offset + n;
                params->fi = fi;

                dokan_send_req(msg);
                ret = dokan_get_result_and_cleanup(msg);

                if (ret > 0)
                        n += ret;
                else
                        break;
        }

        return (ret > 0) ? n : ret;
}

static int
dokan_flush(const char* path, struct fuse_file_info* fi)
{
        dokan_msg_t* msg = NULL;
        dokan_flush_t* params = NULL;

        msg = dokan_get_req(FUSE_FLUSH, sizeof(dokan_flush_t));
        if (msg == NULL)
                return -1;

        params = (dokan_flush_t*)msg->args;
        params->path = path;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_release(const char* path, struct fuse_file_info* fi)
{
        dokan_msg_t* msg = NULL;
        dokan_release_t* params = NULL;

        msg = dokan_get_req(FUSE_RELEASE, sizeof(dokan_release_t));
        if (msg == NULL)
                return -1;

        params = (dokan_release_t*)msg->args;
        params->path = path;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_fsync(const char* path, int isdatasync, struct fuse_file_info* fi)
{
        dokan_msg_t* msg = NULL;
        dokan_fsync_t* params = NULL;

        msg = dokan_get_req(FUSE_FSYNC, sizeof(dokan_fsync_t));
        if (msg == NULL)
                return -1;

        params = (dokan_fsync_t*)msg->args;
        params->path = path;
        params->isdatasync = isdatasync;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_opendir(const char* path, struct fuse_file_info* fi)
{
        int ret = -1;
        dokan_msg_t* msg = NULL;
        dokan_opendir_t* params = NULL;

        msg = dokan_get_req(FUSE_OPENDIR, sizeof(dokan_opendir_t));
        if (msg == NULL)
                return -1;

        params = (dokan_opendir_t*)msg->args;
        params->path = path;
        params->fi = fi;

        dokan_send_req(msg);

        ret = dokan_get_result_and_cleanup(msg);

        if (ret == 0) {
                /* Disable prefetch and put lookup to readdirp
                fd_t *fd = FH_TO_FD(fi->fh);
                dokan_lookup_dir(inode_to_fuse_nodeid(fd->inode));
                fd_unref(fd);
                */
        }

        return ret;
}

int
dokan_lookup_dir(uint64_t nodeid)
{
        dokan_msg_t* msg = NULL;
        dokan_lookup_dir_t* params = NULL;

        msg = dokan_get_req(FUSE_READDIR, sizeof(dokan_lookup_dir_t));
        if (msg == NULL)
                return -1;

        msg->autorelease = _gf_true;

        params = (dokan_lookup_dir_t*)msg->args;
        params->nodeid = nodeid;

        dokan_send_req(msg);

        return 0;
}

void
dokan_perform_lookup(xlator_t *this, char *path, inode_table_t *itable)
{
        inode_t *inode = NULL;
        char *subdir = dirname(path);
        char *bname = NULL;

        inode = fuse_inode_from_path(this, subdir, itable);
        if (inode == NULL)
                dokan_perform_lookup(this, dirname(subdir), itable);
        else {
                bname = basename(path);
                if (strcmp(bname, ".") != 0 &&
                    strcmp(bname, "..") != 0) {
                        if (strcmp(bname, "/") == 0)
                                bname = "";

                        dokan_lookup(this, inode_to_fuse_nodeid(inode), bname);
                }

                inode_unref(inode);
        }

        return NULL;
}

static int
dokan_readdirp(const char* path, void* buf, fuse_fill_dir_t filler,
               off_t offset, struct fuse_file_info* fi)
{
        int ret = -1;
        dokan_msg_t* msg = NULL;
        dokan_readdirp_t* params = NULL;

        if (fi == NULL) {
                return -1;
        }

        msg = dokan_get_req(FUSE_READDIRPLUS, sizeof(dokan_readdirp_t));
        if (msg == NULL)
                return -1;

        params = (dokan_readdirp_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->filler = filler;
        params->offset = offset;
        params->fi = fi;
        params->out_buf = NULL;
        params->out_size = 0;

        dokan_send_req(msg);

        ret = dokan_get_result(msg);

        if (ret == 0 && params->out_size > 0 && filler) {
                size_t size = 0;
                struct fuse_direntplus* fde = NULL;
                struct fuse_entry_out* feo = NULL;
                struct FUSE_STAT stbuf;

                while (size < params->out_size) {
                        fde = (struct fuse_direntplus*)(params->out_buf + size);
                        feo = &fde->entry_out;

                        memset(&stbuf, 0, sizeof(struct FUSE_STAT));
                        gf_fuse_dirent2winstat(&fde->dirent, &stbuf);
                        if (filler(buf, fde->dirent.name, &stbuf, 0)) {
                                break;
                        }

                        size += FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET_DIRENTPLUS +
                                                  fde->dirent.namelen + 1);
                }

                GF_FREE(params->out_buf);
        }

        dokan_cleanup_req(msg);

        return ret;
}

static int
dokan_truncate(const char* path, off_t size)
{
        dokan_msg_t* msg = NULL;
        dokan_ftruncate_t* params = NULL;

        msg = dokan_get_req(FUSE_FALLOCATE, sizeof(dokan_ftruncate_t));
        if (msg == NULL)
                return -1;

        params = (dokan_ftruncate_t*)msg->args;
        params->path = path;
        params->size = size;
        params->fi = NULL;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_ftruncate(const char *path, FUSE_OFF_T size, struct fuse_file_info *fi)
{
        dokan_msg_t* msg = NULL;
        dokan_ftruncate_t* params = NULL;

        msg = dokan_get_req(FUSE_FALLOCATE, sizeof(dokan_ftruncate_t));
        if (msg == NULL)
                return -1;

        params = (dokan_ftruncate_t*)msg->args;
        params->path = path;
        params->size = size;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}


int
dokan_releasedir(const char* path, struct fuse_file_info* fi)
{
        dokan_msg_t* msg = NULL;
        dokan_releasedir_t* params = NULL;

        msg = dokan_get_req(FUSE_RELEASEDIR, sizeof(dokan_releasedir_t));
        if (msg == NULL)
                return -1;

        params = (dokan_releasedir_t*)msg->args;
        params->path = path;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_fsyncdir (const char *path, int isdatasync, struct fuse_file_info *fi)
{
        dokan_msg_t* msg = NULL;
        dokan_fsyncdir_t* params = NULL;

        msg = dokan_get_req(FUSE_FSYNCDIR, sizeof(dokan_fsyncdir_t));
        if (msg == NULL)
                return -1;

        params = (dokan_fsyncdir_t*)msg->args;
        params->path = path;
        params->isdatasync = isdatasync;
        params->fi = fi;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_statfs(const char* path, struct statvfs* stbuf)
{
        dokan_msg_t* msg = NULL;
        dokan_statfs_t* params = NULL;

        msg = dokan_get_req(FUSE_STATFS, sizeof(dokan_statfs_t));
        if (msg == NULL)
                return -1;

        params = (dokan_statfs_t*)msg->args;
        params->path = path;
        params->stbuf = stbuf;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_setxattr(const char* path, const char* name, const char* value,
               size_t size, int flags)
{
        dokan_msg_t* msg = NULL;
        dokan_setxattr_t* params = NULL;

        msg = dokan_get_req(FUSE_SETXATTR, sizeof(dokan_setxattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_setxattr_t*)msg->args;
        params->path = path;
        params->name = name;
        params->value = value;
        params->size = size;
        params->flags = flags;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_getxattr(const char* path, const char* name, char* value, size_t size)
{
        dokan_msg_t* msg = NULL;
        dokan_getxattr_t* params = NULL;

        msg = dokan_get_req(FUSE_GETXATTR, sizeof(dokan_getxattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_getxattr_t*)msg->args;
        params->path = path;
        params->name = name;
        params->value = value;
        params->size = size;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_listxattr(const char* path, char* list, size_t size)
{
        dokan_msg_t* msg = NULL;
        dokan_listxattr_t* params = NULL;

        msg = dokan_get_req(FUSE_LISTXATTR, sizeof(dokan_listxattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_listxattr_t*)msg->args;
        params->path = path;
        params->list = list;
        params->size = size;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_removexattr(const char* path, const char* name)
{
        dokan_msg_t* msg = NULL;
        dokan_removexattr_t* params = NULL;

        msg = dokan_get_req(FUSE_REMOVEXATTR, sizeof(dokan_removexattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_removexattr_t*)msg->args;
        params->path = path;
        params->name = name;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_lock(const char *path, struct fuse_file_info *fi, int cmd,
        struct flock *lock)
{
        dokan_msg_t* msg = NULL;
        dokan_setlk_t* params = NULL;

        msg = dokan_get_req(lock->l_type == F_WRLCK ? FUSE_SETLK : FUSE_SETLKW,
                sizeof(dokan_setlk_t));
        if (msg == NULL)
                return -1;

        params = (dokan_setlk_t*)msg->args;
        params->path = path;
        params->fi = fi;
        params->lk.start = lock->l_start;
        params->lk.end = lock->l_start + lock->l_len;
        params->lk.type = lock->l_type;
        params->lk.pid = lock->l_pid;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_chmod(const char* path, mode_t mode)
{
        dokan_msg_t* msg = NULL;
        dokan_setattr_t* params = NULL;

        msg = dokan_get_req(FUSE_SETATTR, sizeof(dokan_setattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_setattr_t*)msg->args;
        params->path = path;
        params->valid = (FATTR_MODE);
        params->mode = mode;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_chown(const char* path, uid_t uid, gid_t gid)
{
        dokan_msg_t* msg = NULL;
        dokan_setattr_t* params = NULL;

        msg = dokan_get_req(FUSE_SETATTR, sizeof(dokan_setattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_setattr_t*)msg->args;
        params->path = path;
        params->valid = (FATTR_UID | FATTR_GID);
        params->uid = uid;
        params->gid = gid;

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static int
dokan_utimens(const char *path, const struct timespec ts[2])
{
        dokan_msg_t* msg = NULL;
        dokan_setattr_t* params = NULL;
        struct timespec now;

        msg = dokan_get_req(FUSE_SETATTR, sizeof(dokan_setattr_t));
        if (msg == NULL)
                return -1;

        params = (dokan_setattr_t*)msg->args;
        params->path = path;
        params->valid = (FATTR_ATIME | FATTR_MTIME);

        clock_gettime(CLOCK_REALTIME, &now);

        if (ts[0].tv_nsec == UTIME_NOW) {
                params->ts[0] = now;
        }
        else {
                params->ts[0] = ts[0];
        }

        if (ts[1].tv_nsec == UTIME_NOW) {
                params->ts[1] = now;
        }
        else {
                params->ts[1] = ts[1];
        }

        dokan_send_req(msg);

        return dokan_get_result_and_cleanup(msg);
}

static void*
dokan_init(struct fuse_conn_info* conn)
{
        dokan_msg_t* msg = NULL;
        dokan_init_t* params = NULL;

        msg = dokan_get_req(FUSE_INIT, sizeof(dokan_init_t));
        if (msg == NULL)
                return NULL;

        params = (dokan_init_t*)msg->args;
        params->conn = conn;

        dokan_send_req(msg);

        dokan_get_result_and_cleanup(msg);

        return conn;
}

static void
dokan_destroy(void *data)
{
        gf_log("glusterfs-fuse", GF_LOG_INFO,
               "FUSE exited with arg: %p:",
               data);
}

#ifdef _WIN32

static uint32_t
win_get_attributes(const char *fn)
{

}

static int
win_set_attributes(const char *fn, uint32_t attr)
{

}

static int
win_set_times(const char *fn, struct fuse_file_info *,
        const FILETIME *create, const FILETIME *access,
        const FILETIME *modified)
{

}

#endif

int
dokan_send_result(xlator_t* this, dokan_msg_t* msg, int ret)
{
        fuse_private_t* priv = NULL;
        dokan_msg_t* release_msg = NULL;
        dokan_msg_t* wait_msg = NULL;
        dokan_msg_t* inner_msg = NULL;
        dokan_msg_t* n = NULL;
        dokan_autorelease_t *args = NULL;
        int notify = 0;

        gf_log(this->name, GF_LOG_DEBUG,
               "fuse return message %p type: %d, unique: %lu, ret: %d",
                msg, msg->type, msg->unique, ret);

        pthread_mutex_lock(&msg->mutex);
        {
                msg->fin = 1;
                msg->ret = ret;

                if (msg->autorelease) {
                        release_msg = GF_CALLOC(1, sizeof(dokan_msg_t) +
                                sizeof(dokan_autorelease_t), gf_fuse_mt_dokan_msg_t);
                        if (release_msg == NULL)
                                return -1;

                        args = (dokan_autorelease_t *) release_msg->args;
                        args->msg = msg;

                        release_msg->unique = get_fuse_op_unique();
                        release_msg->autorelease = _gf_true;
                        release_msg->fin = 1;
                        release_msg->ret = 0;
                        release_msg->type = FUSE_AUTORELEASE;

                        pthread_mutex_init(&release_msg->mutex, NULL);
                        pthread_cond_init(&release_msg->cond, NULL);
                }

                priv = this->private;

                pthread_mutex_lock(&priv->msg_mutex);
                {
                        if (release_msg) {
                                list_add(&release_msg->list, &priv->msg_list);

                                notify = 1;
                        }

                        list_for_each_entry_safe(wait_msg, n, &priv->wait_list, list) {

                                inner_msg = ((dokan_waitmsg_t*)wait_msg->args)->msg;

                                gf_log(this->name, GF_LOG_DEBUG,
                                       "fuse try to clean message %p type: %d, unique: %lu",
                                        inner_msg, inner_msg->type, inner_msg->unique);

                                if (inner_msg->unique == msg->unique) {
                                        list_del_init(&wait_msg->list);
                                        GF_FREE(wait_msg);

                                        notify = 1;
                                        break;
                                }
                        }

                        if (notify)
                                pthread_cond_broadcast(&priv->msg_cond);
                }
                pthread_mutex_unlock(&priv->msg_mutex);

                if (!msg->autorelease) {
                        pthread_cond_broadcast(&msg->cond);
                }
        }
        pthread_mutex_unlock(&msg->mutex);

        return 0;
}

int
dokan_send_err(xlator_t* this, dokan_msg_t* msg, int error)
{
        inode_t* inode = NULL;

        if (error == ESTALE)
                error = ENOENT;

        inode = fuse_ino_to_inode(msg->finh->nodeid, this);

        // filter out ENOENT
        if (error != ENOENT) {
                if (inode) {
                        fuse_log_eh(this, "Sending %s for operation %d on "
                                          "inode %s",
                                    strerror(error), msg->finh->opcode,
                                    uuid_utoa(inode->gfid));
                } else {
                        fuse_log_eh(this, "Sending %s for operation %d on "
                                          "inode %" GF_PRI_INODE,
                                    strerror(error), msg->finh->opcode,
                                    msg->finh->nodeid);
                }
        }

        if (inode)
                inode_unref(inode);

        dokan_send_result(this, msg, -error);

        return 0;
}

dokan_msg_t*
dokan_get_req(int type, size_t size)
{
        dokan_msg_t* msg = NULL;
        struct fuse_context* ctx = get_fuse_header_in();

        msg = GF_CALLOC(1, sizeof(dokan_msg_t) + size, gf_common_mt_char);
        if (msg == NULL)
                return NULL;

        msg->unique = get_fuse_op_unique();
        msg->autorelease = _gf_false;
        msg->fin = 0;
        msg->ret = -1;
        msg->type = type;

        INIT_FUSE_HEADER(msg->finh, msg->unique, type, ctx);

        pthread_mutex_init(&msg->mutex, NULL);
        pthread_cond_init(&msg->cond, NULL);

        return msg;
}

void
dokan_send_req(dokan_msg_t* msg)
{
        xlator_t* this = get_fuse_xlator();
        fuse_private_t* priv = NULL;

        priv = this->private;

        pthread_mutex_lock(&priv->msg_mutex);
        {
                list_add_tail(&msg->list, &priv->msg_list);

                pthread_cond_broadcast(&priv->msg_cond);
        }
        pthread_mutex_unlock(&priv->msg_mutex);
}

void
dokan_abort_req(dokan_msg_t* msg)
{
        xlator_t* this = get_fuse_xlator();
        fuse_private_t* priv = NULL;
        dokan_msg_t* wait_msg = NULL;
        dokan_msg_t* inner_msg = NULL;
        dokan_msg_t* n = NULL;

        priv = this->private;

        pthread_mutex_lock(&priv->msg_mutex);
        {

                list_for_each_entry_safe(wait_msg, n, &priv->wait_list, list) {

                        inner_msg = ((dokan_waitmsg_t*)wait_msg->args)->msg;

                        gf_log(this->name, GF_LOG_DEBUG,
                               "fuse try to abort message %p type: %d, unique: %lu / %lu",
                                 inner_msg, inner_msg->type, inner_msg->unique, msg->unique);

                        if (inner_msg->unique == msg->unique) {
                                list_del_init(&wait_msg->list);
                                GF_FREE(wait_msg);

                                break;
                        }
                }
        }
        pthread_mutex_unlock(&priv->msg_mutex);
}

int
dokan_get_result(dokan_msg_t* msg)
{
        int ret = -1;
        pthread_mutex_lock(&msg->mutex);
        {
                while (!msg->fin) {
                        ret = pthread_cond_wait(&msg->cond, &msg->mutex);
                        if (ret != 0) {
                                gf_log("fuse-bridage", GF_LOG_DEBUG,
                                       "timedwait returned non zero value "
                                       "ret: %d errno: %d",
                                       ret, errno);

                                ret = -1;
                                break;
                        }

                        ret = msg->ret;
                }
        }
        pthread_mutex_unlock(&msg->mutex);

        return ret;
}

int
dokan_get_result_and_cleanup(dokan_msg_t* msg)
{
        int ret = -1;
        pthread_mutex_lock(&msg->mutex);
        {
                while (!msg->fin) {
                        ret = pthread_cond_wait(&msg->cond, &msg->mutex);
                        if (ret != 0) {
                                gf_log("fuse-bridage", GF_LOG_DEBUG,
                                       "timedwait returned non zero value "
                                       "ret: %d errno: %d",
                                       ret, errno);
                                ret = -1;
                                break;
                        }

                        ret = msg->ret;
                }
        }
        pthread_mutex_unlock(&msg->mutex);

        pthread_mutex_destroy(&msg->mutex);
        pthread_cond_destroy(&msg->cond);

        GF_FREE(msg);

        return ret;
}

void
dokan_cleanup_req(dokan_msg_t* msg)
{
        pthread_mutex_unlock(&msg->mutex);

        pthread_mutex_destroy(&msg->mutex);
        pthread_cond_destroy(&msg->cond);

        GF_FREE(msg);
}

void *
dokan_mount_proc(void* data)
{
        struct mount_data* md = (struct mount_data*)data;

        md->private->fuse = gf_fuse_mount(md->mountpoint, md->fsname, md->mountflags,
                            md->mnt_param, md->status_fd);
        if (md->private->fuse == NULL) {
                gf_log("glusterfs-fuse", GF_LOG_DEBUG, "mount failed (%s)",
                       md->mountpoint);
        }
        gf_log("glusterfs-fuse", GF_LOG_TRACE, "mount process exited.");

        FREE(data);
        return NULL;
}


struct fuse_operations dokan_operations = {
        .getattr        = dokan_getattr,
        .readlink       = dokan_readlink,
        .mknod          = dokan_mknod,
        .mkdir          = dokan_mkdir,
        .unlink         = dokan_unlink,
        .rmdir          = dokan_rmdir,
        .symlink        = dokan_symlink,
        .rename         = dokan_rename,
        .link           = dokan_link,
        .chmod          = dokan_chmod,
        .chown          = dokan_chown,
        .truncate       = dokan_truncate,
        .utime          = NULL,
        .open           = dokan_open,
        .read           = dokan_read,
        .write          = dokan_write,
        .statfs         = dokan_statfs,
        .flush          = dokan_flush,
        .release        = dokan_release,
        .fsync          = dokan_fsync,
        .setxattr       = dokan_setxattr,
        .getxattr       = dokan_getxattr,
        .listxattr      = dokan_listxattr,
        .removexattr    = dokan_removexattr,
        .opendir        = dokan_opendir,
        .readdir        = dokan_readdirp,
        .releasedir     = dokan_releasedir,
        .fsyncdir       = dokan_fsyncdir,
        .init           = dokan_init,
        .destroy        = dokan_destroy,
        .access         = dokan_access,
        .create         = dokan_create,
        .ftruncate      = dokan_ftruncate,
        .fgetattr       = dokan_fgetattr,
        .lock           = dokan_lock,
        .utimens        = dokan_utimens,
        .bmap           = NULL,

#ifdef _WIN32
        /* these to support extented windows calls */
        .win_get_attributes = win_get_attributes,
        .win_set_attributes = win_set_attributes,
        .win_set_times = win_set_times,
#endif
};

