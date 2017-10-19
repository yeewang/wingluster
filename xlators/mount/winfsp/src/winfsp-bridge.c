/*
  Copyright 2016 StorSwift.com

  wangyi8848@gmail.com
*/

#include "byte-order.h"
#include "compat-errno.h"
#include "fuse-bridge.h"
#include "fuse-cache.h"
#include "glusterfs-acl.h"
#include "glusterfs.h"
#include "mount-gluster-compat.h"
#include "winfsp-info.h"
#include <fuse.h>
#include <sys/wait.h>

static int winfsp_releasedir (const char* path, struct fuse_file_info* fi);

void
winfsp_lookup (xlator_t* this, ino_t parent, char* bname)
{
        fuse_private_t* priv = NULL;
        int omit = 0;
        winfsp_msg_t* msg = NULL;
        winfsp_lookup_t* params = NULL;

        priv = this->private;

        msg = winfsp_get_req (THIS, FUSE_LOOKUP, sizeof (winfsp_lookup_t));
        if (msg == NULL)
                return;

        msg->autorelease = _gf_true;

        params = (winfsp_lookup_t*)msg->args;
        params->path = sh_strdup (bname);
        params->lookup_length = strlen(bname);
        params->lookup_offset = 0;
        params->nodeid = parent;

        winfsp_send_req (msg);
}

static int
winfsp_lookup_2 (xlator_t* this, char* path)
{
        winfsp_msg_t* msg = NULL;
        winfsp_lookup_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (THIS, FUSE_LOOKUP, sizeof (winfsp_lookup_t));
        if (msg == NULL)
                return;

        params = (winfsp_lookup_t*)msg->args;
        params->path = sh_strdup (path);
        params->lookup_length = strlen(path);
        params->lookup_offset = 0;
        params->nodeid = 0;

        winfsp_send_req (msg);
        ret = winfsp_get_result_and_cleanup (msg);
        return ret;
}

void
winfsp_forget (uint64_t nodeid, uint64_t nlookup)
{
        winfsp_msg_t* msg = NULL;
        winfsp_forget_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_FORGET, sizeof (winfsp_forget_t));
        if (msg == NULL)
                return;

        params = (winfsp_forget_t*)msg->args;
        params->nodeid = nodeid;
        params->nlookup = nlookup;

        winfsp_send_req (msg);
}

void
winfsp_batch_forget (winfsp_forget_t* items, size_t count)
{
        winfsp_msg_t* msg = NULL;
        winfsp_batch_forget_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_BATCH_FORGET,
                              sizeof (winfsp_batch_forget_t) +
                                sizeof (winfsp_forget_t) * count);
        if (msg == NULL)
                return;

        params = (winfsp_batch_forget_t*)msg->args;
        params->count = count;
        memcpy (params->items, items, sizeof (winfsp_forget_t) * count);

        winfsp_send_req (msg);
}

static int
winfsp_getattr (const char* path, struct fuse_stat* stbuf)
{
        winfsp_msg_t* msg = NULL;
        winfsp_getattr_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (THIS, FUSE_GETATTR, sizeof (winfsp_getattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_getattr_t*)msg->args;
        params->path = path;
        params->stbuf = stbuf;
        params->fi = NULL;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_fgetattr (const char* path, struct fuse_stat* stbuf,
                 struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_getattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_GETATTR, sizeof (winfsp_getattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_getattr_t*)msg->args;
        params->path = path;
        params->stbuf = stbuf;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_access (const char* path, int mask)
{
        winfsp_msg_t* msg = NULL;
        winfsp_access_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_ACCESS, sizeof (winfsp_access_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_access_t*)msg->args;
        params->path = path;
        params->mask = mask;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_readlink (const char* path, char* buf, size_t size)
{
        winfsp_msg_t* msg = NULL;
        winfsp_readlink_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_READLINK, sizeof (winfsp_readlink_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_readlink_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->size = size;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_mknod (const char* path, mode_t mode, dev_t rdev)
{
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_mknod_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (this, FUSE_MKNOD, sizeof (winfsp_mknod_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_mknod_t*)msg->args;
        params->path = path;
        params->mode = mode;
        params->rdev = rdev;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        winfsp_lookup_2 (this, path);

        winfsp_cleanup_req (msg);

        return ret;
}

static int
winfsp_mkdir (const char* path, mode_t mode)
{
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_mkdir_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (this, FUSE_MKDIR, sizeof (winfsp_mkdir_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_mkdir_t*)msg->args;
        params->path = path;
        params->mode = mode;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        winfsp_lookup_2 (this, path);

        winfsp_cleanup_req (msg);

        return ret;
}

static int
winfsp_unlink (const char* path)
{
        winfsp_msg_t* msg = NULL;
        winfsp_unlink_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_UNLINK, sizeof (winfsp_unlink_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_unlink_t*)msg->args;
        params->path = path;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_rmdir (const char* path)
{
        winfsp_msg_t* msg = NULL;
        winfsp_rmdir_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_RMDIR, sizeof (winfsp_rmdir_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_rmdir_t*)msg->args;
        params->path = path;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_symlink (const char* from, const char* to)
{
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_symlink_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (this, FUSE_RMDIR, sizeof (winfsp_symlink_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_symlink_t*)msg->args;
        params->from = from;
        params->to = to;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        winfsp_lookup_2 (this, from);
        winfsp_lookup_2 (this, to);

        winfsp_cleanup_req (msg);

        return ret;
}

static int
winfsp_rename (const char* from, const char* to)
{
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_rename_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (this, FUSE_RENAME, sizeof (winfsp_rename_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_rename_t*)msg->args;
        params->from = from;
        params->to = to;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        winfsp_lookup_2 (this, from);
        winfsp_lookup_2 (this, to);

        winfsp_cleanup_req (msg);

        return ret;
}

static int
winfsp_link (const char* from, const char* to)
{
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_link_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (this, FUSE_LINK, sizeof (winfsp_link_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_link_t*)msg->args;
        params->from = from;
        params->to = to;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        winfsp_lookup_2 (this, from);
        winfsp_lookup_2 (this, to);

        winfsp_cleanup_req (msg);

        return ret;
}

static int
winfsp_create (const char* path, mode_t mode, struct fuse_file_info* fi)
{
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_create_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (this, FUSE_CREATE, sizeof (winfsp_create_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_create_t*)msg->args;
        params->path = path;
        params->mode = mode;
        params->fi = fi;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        winfsp_lookup_2 (this, path);

        winfsp_cleanup_req (msg);

        return ret;
}

static int
winfsp_open (const char* path, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_open_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_OPEN, sizeof (winfsp_open_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_open_t*)msg->args;
        params->path = path;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_read_base (const char* path, char* buf, size_t size, off_t offset,
                  struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_read_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (THIS, FUSE_READ, sizeof (winfsp_read_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_read_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->size = size;
        params->offset = offset;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

#ifdef USE_READCACHE

static int
winfsp_read_cached (const char* path, char* buf, size_t size, off_t offset,
                    struct fuse_file_info* fi)
{
        xlator_t* this = get_fuse_xlator ();
        fuse_private_t* priv = NULL;
        int ret = -1;

        priv = this->private;

        uv_mutex_lock (&priv->read_cache.lock);
        {
                if (priv->read_cache.iobuf == NULL) {
                        priv->read_cache.iobuf =
                          iobuf_get2 (this->ctx->iobuf_pool, MAX_READ_PAGE);
                        if (priv->read_cache.iobuf == NULL) {
                                goto unlock;
                        }

                        priv->read_cache.path = path;
                        priv->read_cache.handle = fi->fh;
                        priv->read_cache.offset = offset;
                        priv->read_cache.size = winfsp_read_base (
                          path, iobuf_ptr (priv->read_cache.iobuf),
                          MAX_READ_PAGE, offset, fi);

                        if (priv->read_cache.size < 0) {
                                ret = priv->read_cache.size;
                                iobuf_unref (priv->read_cache.iobuf);
                                priv->read_cache.iobuf = NULL;
                                priv->read_cache.handle = INVALIDE_HANDLE;
                                priv->read_cache.offset = 0;
                                priv->read_cache.size = 0;
                                goto unlock;
                        }
                }

                if (fi->fh == priv->read_cache.handle &&
                    offset >= priv->read_cache.offset &&
                    offset + size <=
                      priv->read_cache.offset + priv->read_cache.size) {
                        memcpy (buf, iobuf_ptr (priv->read_cache.iobuf) +
                                       offset - priv->read_cache.offset,
                                size);
                        ret = size;
                } else {
                        if (priv->read_cache.iobuf)
                                iobuf_unref (priv->read_cache.iobuf);

                        priv->read_cache.iobuf =
                          iobuf_get2 (this->ctx->iobuf_pool, MAX_READ_PAGE);
                        if (priv->read_cache.iobuf == NULL) {
                                goto unlock;
                        }

                        priv->read_cache.path = path;
                        priv->read_cache.handle = fi->fh;
                        priv->read_cache.offset = offset;
                        priv->read_cache.size = winfsp_read_base (
                          path, iobuf_ptr (priv->read_cache.iobuf),
                          MAX_READ_PAGE, offset, fi);

                        if (priv->read_cache.size < 0) {
                                ret = priv->read_cache.size;
                                iobuf_unref (priv->read_cache.iobuf);
                                priv->read_cache.iobuf = NULL;
                                priv->read_cache.handle = INVALIDE_HANDLE;
                                priv->read_cache.offset = 0;
                                priv->read_cache.size = 0;
                                goto unlock;
                        }

                        memcpy (buf, iobuf_ptr (priv->read_cache.iobuf) +
                                       offset - priv->read_cache.offset,
                                size);
                        ret = size;
                }
        }
unlock:
        uv_mutex_unlock (&priv->read_cache.lock);

        return ret;
}
#endif

static int
winfsp_read (const char* path, char* buf, size_t size, off_t offset,
             struct fuse_file_info* fi)
{
        int ret = -1;
#ifdef USE_READCACHE
        size_t seg_size = 0, off = 0, last = 0;

        if (size < MAX_READ_PAGE) {
                ret = winfsp_read_cached (path, buf, size, offset, fi);
        } else {
                last = size;
                while (last > 0) {
                        seg_size = last > MAX_READ_PAGE ?
                                     MAX_READ_PAGE : last;
                        ret = winfsp_read_base (path, buf + off, seg_size,
                                                offset + off, fi);
                        if (ret < 0)
                                break;

                        off += seg_size;
                        last -= seg_size;
                }
                if (ret > 0)
                        ret = size;
        }
#else
        ret = winfsp_read_base (path, buf, size, offset, fi);
#endif /* USE_READCACHE */

        return ret;
}

static int
winfsp_write_base (const char* path, const char* buf, size_t size, off_t offset,
                   struct fuse_file_info* fi)
{
        xlator_t* this = get_fuse_xlator ();
        winfsp_msg_t* msg = NULL;
        winfsp_write_t* params = NULL;
        int ret = -1;

        msg = winfsp_get_req (THIS, FUSE_WRITE, sizeof (winfsp_write_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_write_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->size = size;
        params->offset = offset;
        params->fi = fi;

        winfsp_send_req (msg);
        ret = winfsp_get_result_and_cleanup (msg);

        return ret;
}

static int
winfsp_write_ex (xlator_t* this, const char* path, struct iobuf* buf,
                 size_t size, off_t offset, uint64_t handle, int sync)
{
        fuse_private_t* priv = NULL;
        winfsp_msg_t* msg = NULL;
        winfsp_write_ex_t* params = NULL;
        int ret = -1;

        priv = this->private;

        msg = winfsp_get_req (THIS, FUSE_WRITE_EX, sizeof (winfsp_write_ex_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_write_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->size = size;
        params->offset = offset;
        params->handle = handle;

        winfsp_send_req (msg);

        if (sync)
                ret = winfsp_get_result_and_cleanup (msg);
        else
                ret = 0;

        return ret;
}

static int
winfsp_write_cached (const char* path, const char* buf, size_t size,
                     off_t offset, struct fuse_file_info* fi)
{
        xlator_t* this = get_fuse_xlator ();
        fuse_private_t* priv = NULL;
        struct iobuf* t_iobuf;
        const char* t_path;
        uint64_t t_handle;
        size_t t_offset;
        size_t t_size;
        int flush = 1;
        int ret = -1;

        priv = this->private;

        uv_mutex_lock (&priv->write_cache.lock);
        {
                if (priv->write_cache.iobuf == NULL) {
                        priv->write_cache.iobuf =
                          iobuf_get2 (this->ctx->iobuf_pool, MAX_WRITE_PAGE);
                        if (priv->write_cache.iobuf == NULL) {
                                goto unlock;
                        }

                        priv->write_cache.path = NULL;
                        priv->write_cache.handle = fi->fh;
                        priv->write_cache.offset = offset;
                        priv->write_cache.size = 0;

                        flush = 0;
                } else if (fi->fh == priv->write_cache.handle &&
                           offset ==
                             priv->write_cache.offset +
                               priv->write_cache.size &&
                           priv->write_cache.size + size <=
                             iobuf_size (priv->write_cache.iobuf)) {
                        flush = 0;
                }

                if (flush) {
                        t_iobuf = priv->write_cache.iobuf;
                        t_path = priv->write_cache.path;
                        t_handle = priv->write_cache.handle;
                        t_offset = priv->write_cache.offset;
                        t_size = priv->write_cache.size;
                        priv->write_cache.iobuf = NULL;

                        uv_mutex_unlock (&priv->write_cache.lock);

                        winfsp_write_ex (this, t_path, t_iobuf, t_size,
                                         t_offset, t_handle, 1);

                        uv_mutex_lock (&priv->write_cache.lock);

                        priv->write_cache.iobuf =
                          iobuf_get2 (this->ctx->iobuf_pool, MAX_WRITE_PAGE);
                        if (priv->write_cache.iobuf == NULL) {
                                goto unlock;
                        }

                        priv->write_cache.path = NULL;
                        priv->write_cache.handle = fi->fh;
                        priv->write_cache.offset = offset;
                        priv->write_cache.size = 0;
                }

                memcpy (iobuf_ptr (priv->write_cache.iobuf) +
                          priv->write_cache.size,
                        buf, size);
                priv->write_cache.size += size;
                ret = size;
        }
unlock:
        uv_mutex_unlock (&priv->write_cache.lock);

        return ret;
}

static int
winfsp_write (const char* path, const char* buf, size_t size, off_t offset,
              struct fuse_file_info* fi)
{
        int ret = -1;
        size_t seg_size = 0, off = 0, last = 0;

        if (size < MAX_WRITE_PAGE) {
                ret = winfsp_write_cached (path, buf, size, offset, fi);
        } else {
                last = size;
                while (last > 0) {
                        seg_size = last > MAX_WRITE_PAGE ?
                                     MAX_WRITE_PAGE : last;
                        ret = winfsp_write_base (path, buf + off, seg_size,
                                                 offset + off, fi);
                        if (ret < 0)
                                break;

                        off += seg_size;
                        last -= seg_size;
                }
                if (ret > 0)
                        ret = size;
        }

        return ret;
}

static int
winfsp_flush (const char* path, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_flush_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_FLUSH, sizeof (winfsp_flush_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_flush_t*)msg->args;
        params->path = path;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_release (const char* path, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_release_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_RELEASE, sizeof (winfsp_release_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_release_t*)msg->args;
        params->path = path;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_fsync (const char* path, int isdatasync, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_fsync_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_FSYNC, sizeof (winfsp_fsync_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_fsync_t*)msg->args;
        params->path = path;
        params->isdatasync = isdatasync;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_opendir (const char* path, struct fuse_file_info* fi)
{
        int ret = -1;
        xlator_t* this = THIS;
        winfsp_msg_t* msg = NULL;
        winfsp_opendir_t* params = NULL;

        ret = winfsp_lookup_2 (this, path);
        if (ret == ENOENT)
                return ret;

        msg = winfsp_get_req (THIS, FUSE_OPENDIR, sizeof (winfsp_opendir_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_opendir_t*)msg->args;
        params->path = path;
        params->fi = fi;

        winfsp_send_req (msg);

        ret = winfsp_get_result_and_cleanup (msg);

        if (ret == 0) {
                /* Disable prefetch and put lookup to readdirp
                fd_t *fd = FH_TO_FD(fi->fh);
                winfsp_lookup_dir(inode_to_fuse_nodeid(fd->inode));
                fd_unref(fd);
                */
        }

        return ret;
}

int
winfsp_lookup_dir (uint64_t nodeid)
{
        winfsp_msg_t* msg = NULL;
        winfsp_lookup_dir_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_READDIR, sizeof (winfsp_lookup_dir_t));
        if (msg == NULL)
                return -1;

        msg->autorelease = _gf_true;

        params = (winfsp_lookup_dir_t*)msg->args;
        params->nodeid = nodeid;

        winfsp_send_req (msg);

        return 0;
}

void
winfsp_perform_lookup (xlator_t* this, char* path, inode_table_t* itable)
{
        inode_t* inode = NULL;
        char* subdir = dirname (path);
        char* bname = NULL;

        inode = fuse_inode_from_path (this, subdir, itable);
        if (inode == NULL)
                winfsp_perform_lookup (this, dirname (subdir), itable);
        else {
                bname = basename (path);
                if (strcmp (bname, ".") != 0 && strcmp (bname, "..") != 0) {
                        if (strcmp (bname, "/") == 0)
                                bname = "";

                        winfsp_lookup (this, inode_to_fuse_nodeid (inode),
                                       bname);
                }

                inode_unref (inode);
        }

        return;
}

static int
winfsp_readdirp_ex (const char* path, void* buf, fuse_fill_dir_t filler,
                    fuse_off_t offset, struct fuse_file_info* fi)
{
        int ret = -1;
        winfsp_msg_t* msg = NULL;
        winfsp_readdirp_t* params = NULL;
        size_t size = 0;
        int end = 0;

        if (fi == NULL) {
                return -1;
        }

        msg =
          winfsp_get_req (THIS, FUSE_READDIRPLUS, sizeof (winfsp_readdirp_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_readdirp_t*)msg->args;
        params->path = path;
        params->buf = buf;
        params->filler = filler;
        params->offset = offset;
        params->fi = fi;
        params->out_buf = NULL;
        params->out_size = 0;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        if (ret == 0 && params->out_size > size && filler) {
                struct fuse_direntplus* fde = NULL;
                struct fuse_entry_out* feo = NULL;
                struct stat stbuf;

                while (size < params->out_size) {
                        fde = (struct fuse_direntplus*)(params->out_buf + size);
                        feo = &fde->entry_out;

                        memset (&stbuf, 0, sizeof (struct stat));
                        gf_fuse_dirent2winstat (&fde->dirent, &stbuf);
                        if (filler (buf, fde->dirent.name, &stbuf, 0)) {
                                break;
                        }

                        size += FUSE_DIRENT_ALIGN (FUSE_NAME_OFFSET_DIRENTPLUS +
                                                   fde->dirent.namelen + 1);
                }
        }

        if (params->out_buf != NULL)
                SH_FREE (params->out_buf);

        winfsp_cleanup_req (msg);

        return ret;
}

static off_t
winfsp_readdirp_cache (const char* path, fuse_cache_dirh_t* buf,
                       fuse_cache_dirfil_t filler, fuse_off_t offset,
                       struct fuse_file_info* fi)
{
        int ret = -1;
        off_t off = 0;
        winfsp_msg_t* msg = NULL;
        winfsp_readdirp_t* params = NULL;
        size_t size = 0;
        int end = 0;

        if (fi == NULL) {
                return -1;
        }

        msg =
          winfsp_get_req (THIS, FUSE_READDIRPLUS, sizeof (winfsp_readdirp_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_readdirp_t*)msg->args;
        params->path = path;
        params->buf = buf;
        /* Did not use this paramenter.
         * params->filler = filler; */
        params->filler = NULL;
        params->offset = offset;
        params->fi = fi;
        params->out_off = 0;
        params->out_buf = NULL;
        params->out_size = 0;

        winfsp_send_req (msg);

        ret = winfsp_get_result (msg);

        if (ret > 0 && params->out_size > size && filler) {
                struct fuse_direntplus* fde = NULL;
                struct fuse_entry_out* feo = NULL;
                struct stat stbuf;

                while (size < params->out_size) {
                        fde = (struct fuse_direntplus*)(params->out_buf + size);
                        feo = &fde->entry_out;

                        memset (&stbuf, 0, sizeof (struct stat));
                        gf_fuse_dirent2winstat (&fde->dirent, &stbuf);
                        if (filler (buf, fde->dirent.name, &stbuf)) {
                                break;
                        }

                        size += FUSE_DIRENT_ALIGN (FUSE_NAME_OFFSET_DIRENTPLUS +
                                                   fde->dirent.namelen + 1);
                }

                off = params->out_off;
        }

        if (params->out_buf != NULL)
                SH_FREE (params->out_buf);

        winfsp_cleanup_req (msg);

        return ret > 0 ? off : ret;
}

static int
winfsp_readdirp (const char* path, void* buf, fuse_fill_dir_t filler,
                 fuse_off_t offset, struct fuse_file_info* fi)
{
        int ret = 0;

        if (fi == NULL || fi->fh == INVALIDE_HANDLE) {
                struct fuse_file_info newfi = *fi;

                ret = winfsp_opendir (path, &newfi);

                if (ret == 0) {
                        ret = winfsp_readdirp_ex (path, buf, filler, offset,
                                                  &newfi);

                        winfsp_releasedir (path, &newfi);
                }
        } else {
                ret = winfsp_readdirp_ex (path, buf, filler, offset, fi);
        }

        return ret;
}

int
winfsp_getdir (const char* path, fuse_cache_dirh_t buf,
               fuse_cache_dirfil_t filler)
{
        off_t off = 0;
        int ret = 0;

        struct fuse_file_info fi;
        ret = winfsp_opendir (path, &fi);

        if (ret == 0) {
                do {
                        off =
                          winfsp_readdirp_cache (path, buf, filler, off, &fi);
                } while (off > 0);

                winfsp_releasedir (path, &fi);
        }

        return ret;
}

static int
winfsp_getdir1 (const char* path, fuse_dirh_t buf, fuse_dirfil_t filler)
{
        int ret = 0;

        struct fuse_file_info fi;
        ret = winfsp_opendir (path, &fi);

        if (ret == 0) {
                ret = winfsp_readdirp_ex (path, buf, filler, 0, &fi);

                winfsp_releasedir (path, &fi);
        }

        return ret;
}

static int
winfsp_truncate (const char* path, off_t size)
{
        xlator_t* this = NULL;
        winfsp_msg_t* msg = NULL;
        winfsp_setattr_t* params = NULL;

        this = THIS;
        msg = winfsp_get_req (this, FUSE_SETATTR, sizeof (winfsp_setattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setattr_t*)msg->args;
        params->path = path;
        params->valid = (FATTR_SIZE);
        params->off = size;
        params->fi = NULL;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_ftruncate (const char* path, off_t size, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_setattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_SETATTR, sizeof (winfsp_setattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setattr_t*)msg->args;
        params->fi = fi;
        params->path = path;
        params->valid = (FATTR_SIZE);
        params->off = size;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_releasedir (const char* path, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_releasedir_t* params = NULL;

        msg =
          winfsp_get_req (THIS, FUSE_RELEASEDIR, sizeof (winfsp_releasedir_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_releasedir_t*)msg->args;
        params->path = path;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_fsyncdir (const char* path, int isdatasync, struct fuse_file_info* fi)
{
        winfsp_msg_t* msg = NULL;
        winfsp_fsyncdir_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_FSYNCDIR, sizeof (winfsp_fsyncdir_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_fsyncdir_t*)msg->args;
        params->path = path;
        params->isdatasync = isdatasync;
        params->fi = fi;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_statfs (const char* path, struct statvfs* stbuf)
{
        winfsp_msg_t* msg = NULL;
        winfsp_statfs_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_STATFS, sizeof (winfsp_statfs_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_statfs_t*)msg->args;
        params->path = path;
        params->stbuf = stbuf;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_setxattr (const char* path, const char* name, const char* value,
                 size_t size, int flags)
{
        winfsp_msg_t* msg = NULL;
        winfsp_setxattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_SETXATTR, sizeof (winfsp_setxattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setxattr_t*)msg->args;
        params->path = path;
        params->name = name;
        params->value = value;
        params->size = size;
        params->flags = flags;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_getxattr (const char* path, const char* name, char* value, size_t size)
{
        winfsp_msg_t* msg = NULL;
        winfsp_getxattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_GETXATTR, sizeof (winfsp_getxattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_getxattr_t*)msg->args;
        params->path = path;
        params->name = name;
        params->value = value;
        params->size = size;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_listxattr (const char* path, char* list, size_t size)
{
        winfsp_msg_t* msg = NULL;
        winfsp_listxattr_t* params = NULL;

        msg =
          winfsp_get_req (THIS, FUSE_LISTXATTR, sizeof (winfsp_listxattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_listxattr_t*)msg->args;
        params->path = path;
        params->list = list;
        params->size = size;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_removexattr (const char* path, const char* name)
{
        winfsp_msg_t* msg = NULL;
        winfsp_removexattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_REMOVEXATTR,
                              sizeof (winfsp_removexattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_removexattr_t*)msg->args;
        params->path = path;
        params->name = name;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_lock (const char* path, struct fuse_file_info* fi, int cmd,
             struct flock* lock)
{
        winfsp_msg_t* msg = NULL;
        winfsp_setlk_t* params = NULL;

        msg = winfsp_get_req (THIS, lock->l_type == F_WRLCK ? FUSE_SETLK
                                                            : FUSE_SETLKW,
                              sizeof (winfsp_setlk_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setlk_t*)msg->args;
        params->path = path;
        params->fi = fi;
        params->lk.start = lock->l_start;
        params->lk.end = lock->l_start + lock->l_len;
        params->lk.type = lock->l_type;
        params->lk.pid = lock->l_pid;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_chmod (const char* path, mode_t mode)
{
        winfsp_msg_t* msg = NULL;
        winfsp_setattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_SETATTR, sizeof (winfsp_setattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setattr_t*)msg->args;
        params->path = path;
        params->valid = (FATTR_MODE);
        params->mode = mode;
        params->fi = NULL;

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static int
winfsp_chown (const char* path, uid_t uid, gid_t gid)
{
        winfsp_msg_t* msg = NULL;
        winfsp_setattr_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_SETATTR, sizeof (winfsp_setattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setattr_t*)msg->args;
        params->path = path;
        params->valid = (FATTR_UID | FATTR_GID);
        params->uid = uid;
        params->gid = gid;
        params->fi = NULL;

        winfsp_send_req (msg);

        winfsp_get_result_and_cleanup (msg);

        /* disable error return. */
        return 0;
}

static int
winfsp_utimens (const char* path, const struct timespec ts[2])
{
        winfsp_msg_t* msg = NULL;
        winfsp_setattr_t* params = NULL;
        struct timespec now;

        msg = winfsp_get_req (THIS, FUSE_SETATTR, sizeof (winfsp_setattr_t));
        if (msg == NULL)
                return -1;

        params = (winfsp_setattr_t*)msg->args;
        params->fi = NULL;
        params->path = path;
        params->valid = (FATTR_ATIME | FATTR_MTIME);

        clock_gettime (CLOCK_REALTIME, &now);

        if (ts[0].tv_nsec == UTIME_NOW) {
                params->ts[0] = now;
        } else {
                params->ts[0] = ts[0];
        }

        if (ts[1].tv_nsec == UTIME_NOW) {
                params->ts[1] = now;
        } else {
                params->ts[1] = ts[1];
        }

        winfsp_send_req (msg);

        return winfsp_get_result_and_cleanup (msg);
}

static void*
winfsp_init (struct fuse_conn_info* conn)
{
        winfsp_msg_t* msg = NULL;
        winfsp_init_t* params = NULL;

        msg = winfsp_get_req (THIS, FUSE_INIT, sizeof (winfsp_init_t));
        if (msg == NULL)
                return NULL;

        params = (winfsp_init_t*)msg->args;
        params->conn = conn;

        winfsp_send_req (msg);

        winfsp_get_result_and_cleanup (msg);

        return conn;
}

static void
winfsp_destroy (void* data)
{
        gf_log ("glusterfs-fuse", GF_LOG_INFO, "FUSE exited with arg: %p:",
                data);
}

static int
list_count (struct list_head* head)
{
        struct list_head* node = NULL;
        int count = 0;

        list_for_each (node, head) { count++; }
        return count;
}

int
winfsp_send_result (xlator_t* this, winfsp_msg_t* msg, int ret)
{
        fuse_private_t* priv = NULL;
        struct iobuf* iobuf = NULL;
        winfsp_msg_t* release_msg = NULL;
        winfsp_msg_t* wait_msg = NULL;
        winfsp_msg_t* inner_msg = NULL;
        winfsp_msg_t* n = NULL;
        winfsp_autorelease_t* args = NULL;
        int notify = 0;
        int retval = 0;

#if 0
        gf_log (this->name, GF_LOG_INFO,
                "fuse return message %p type: %d, unique: %lu, ret: %d %s", msg,
                msg->type, msg->unique, ret, ret != 0 ? strerror(-ret) : "");
#endif /* DEBUG */

        priv = this->private;

        uv_mutex_lock (&priv->msg_mutex);
        {
                uv_mutex_lock (&msg->mutex);
                {
                        msg->fin = 1;
                        msg->ret = ret;

                        if (msg->autorelease) {
#ifndef USE_IOBUF
                                release_msg =
                                  SH_CALLOC (1, sizeof (winfsp_msg_t) +
                                                  sizeof (winfsp_autorelease_t),
                                             gf_fuse_mt_winfsp_msg_t);
                                if (release_msg == NULL) {
                                        retval = -1;
                                        goto unlock;
                                }
#else
                                iobuf =
                                  iobuf_get2 (this->ctx->iobuf_pool,
                                              sizeof (winfsp_msg_t) +
                                                sizeof (winfsp_autorelease_t));
                                if (iobuf == NULL) {
                                        retval = -1;
                                        goto unlock;
                                }
                                release_msg = iobuf_ptr (iobuf);
                                release_msg->iobuf = iobuf;
#endif /* USE_IOBUF */
                                INIT_LIST_HEAD (&release_msg->list);
                                args = (winfsp_autorelease_t*)release_msg->args;
                                args->msg = msg;

                                release_msg->unique = get_fuse_op_unique ();
                                release_msg->autorelease = _gf_true;
                                release_msg->fin = 1;
                                release_msg->ret = 0;
                                release_msg->type = FUSE_AUTORELEASE;

                                uv_mutex_init (&release_msg->mutex);
                                uv_cond_init (&release_msg->cond);
                        }
                }
unlock:
                uv_mutex_unlock (&msg->mutex);

                if (release_msg) {
                        list_add (&release_msg->list, &priv->msg_list);

                        notify = 1;
                }

                list_for_each_entry_safe (wait_msg, n, &priv->wait_list, list)
                {

                        inner_msg = ((winfsp_waitmsg_t*)wait_msg->args)->msg;

                        /*
                        gf_log(this->name, GF_LOG_DEBUG,
                               "fuse try to clean message %p type: %d,
                        unique: %lu",
                                inner_msg, inner_msg->type,
                        inner_msg->unique);
                        */

                        if (inner_msg->unique == msg->unique) {
                                list_del_init (&wait_msg->list);
#ifndef USE_IOBUF
                                SH_FREE (wait_msg);
#else
                                iobuf_unref (wait_msg->iobuf);
#endif /* USE_IOBUF */
                                notify = 1;
                                break;
                        }
                }

                if (notify)
                        uv_sem_post (&priv->msg_sem);

                if (!msg->autorelease) {
                        uv_cond_signal (&msg->cond);
                }
        }
        uv_mutex_unlock (&priv->msg_mutex);

        return retval;
}

int
winfsp_send_err (xlator_t* this, winfsp_msg_t* msg, int error)
{
        inode_t* inode = NULL;

        if (error == ESTALE)
                error = ENOENT;

        inode = fuse_ino_to_inode (msg->finh->nodeid, this);

        // filter out ENOENT
        if (error != ENOENT) {
                if (inode) {
                        fuse_log_eh (this, "Sending %s for operation %d on "
                                           "inode %s",
                                     strerror (error), msg->finh->opcode,
                                     uuid_utoa (inode->gfid));
                } else {
                        fuse_log_eh (this, "Sending %s for operation %d on "
                                           "inode %" GF_PRI_INODE,
                                     strerror (error), msg->finh->opcode,
                                     msg->finh->nodeid);
                }
        }

        if (inode)
                inode_unref (inode);

        winfsp_send_result (this, msg, -error);

        return 0;
}

winfsp_msg_t*
winfsp_get_req (xlator_t* this, int type, size_t size)
{
        winfsp_msg_t* msg = NULL;
#ifdef USE_IOBUF
        struct iobuf* iobuf = NULL;
#endif
        struct fuse_context* ctx = get_fuse_header_in ();

#ifndef USE_IOBUF
        msg = SH_CALLOC (1, sizeof (winfsp_msg_t) + size, gf_common_mt_char);
        if (msg == NULL)
                return NULL;
#else
        iobuf =
          iobuf_get2 (this->ctx->iobuf_pool, sizeof (winfsp_msg_t) + size);
        if (iobuf == NULL)
                return NULL;
        msg = iobuf_ptr (iobuf);
        msg->iobuf = iobuf;
#endif /* USE_IOBUF */
        INIT_LIST_HEAD (&msg->list);
        msg->timeout = 20 * 1000;
        msg->error_count = 0;
        msg->unique = get_fuse_op_unique ();
        msg->autorelease = _gf_false;
        msg->fin = 0;
        msg->ret = -1;
        msg->type = type;

        INIT_FUSE_HEADER (msg->finh, msg->unique, type, ctx);

#ifdef NEVER
        // msg->finh->pid = 0;
        msg->finh->uid = 0;
        msg->finh->gid = 0;

        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                "winfsp_get_req with Auth Info: pid=%d, uid=%d, gid=%d",
                msg->finh->pid, msg->finh->uid, msg->finh->gid);
#endif /* NEVER */

        uv_mutex_init (&msg->mutex);
        uv_cond_init (&msg->cond);

        return msg;
}

void
winfsp_send_req (winfsp_msg_t* msg)
{
        xlator_t* this = get_fuse_xlator ();
        fuse_private_t* priv = NULL;

        priv = this->private;

        uv_mutex_lock (&priv->msg_mutex);
        {
                list_add_tail (&msg->list, &priv->msg_list);

                uv_sem_post (&priv->msg_sem);
        }
        uv_mutex_unlock (&priv->msg_mutex);
}

void
winfsp_inseart_req (winfsp_msg_t* msg)
{
        xlator_t* this = get_fuse_xlator ();
        fuse_private_t* priv = NULL;

        priv = this->private;

        uv_mutex_lock (&priv->msg_mutex);
        {
                list_add (&msg->list, &priv->msg_list);

                uv_sem_post (&priv->msg_sem);
        }
        uv_mutex_unlock (&priv->msg_mutex);
}

void
winfsp_abort_req (winfsp_msg_t* msg)
{
        xlator_t* this = get_fuse_xlator ();
        fuse_private_t* priv = NULL;
        winfsp_msg_t* wait_msg = NULL;
        winfsp_msg_t* inner_msg = NULL;
        winfsp_msg_t* n = NULL;

        priv = this->private;

        uv_mutex_lock (&priv->msg_mutex);
        {

                list_for_each_entry_safe (wait_msg, n, &priv->wait_list, list)
                {

                        inner_msg = ((winfsp_waitmsg_t*)wait_msg->args)->msg;

                        gf_log (this->name, GF_LOG_DEBUG,
                                "fuse try to abort message %p type: %d, "
                                "unique: %lu / %lu",
                                inner_msg, inner_msg->type, inner_msg->unique,
                                msg->unique);

                        if (inner_msg->unique == msg->unique) {
                                list_del_init (&wait_msg->list);
#ifndef USE_IOBUF
                                SH_FREE (wait_msg);
#else
                                iobuf_unref (wait_msg->iobuf);
#endif /* USE_IOBUF */

                                break;
                        }
                }
        }
        uv_mutex_unlock (&priv->msg_mutex);
}

int
winfsp_get_result (winfsp_msg_t* msg)
{
        int ret = -1;
        uv_mutex_lock (&msg->mutex);
        {
                while (!msg->fin) {
                        uv_cond_wait (&msg->cond, &msg->mutex);
                }
                ret = msg->ret;
        }
        uv_mutex_unlock (&msg->mutex);

        return ret;
}

int
winfsp_get_result_and_cleanup (winfsp_msg_t* msg)
{
        int ret = -1;
        uv_mutex_lock (&msg->mutex);
        {
                while (!msg->fin) {
                        uv_cond_wait (&msg->cond, &msg->mutex);
                }
                ret = msg->ret;
        }
        uv_mutex_unlock (&msg->mutex);

        uv_mutex_destroy (&msg->mutex);
        uv_cond_destroy (&msg->cond);

#ifndef USE_IOBUF
        SH_FREE (msg);
#else
        iobuf_unref (msg->iobuf);
#endif /* USE_IOBUF */

        return ret;
}

void
winfsp_cleanup_req (winfsp_msg_t* msg)
{
        uv_mutex_destroy (&msg->mutex);
        uv_cond_destroy (&msg->cond);

#ifndef USE_IOBUF
        SH_FREE (msg);
#else
        iobuf_unref (msg->iobuf);
#endif /* USE_IOBUF */
}

void*
winfsp_mount_proc (void* data)
{
        struct mount_data* md = (struct mount_data*)data;

        md->private->fuse =
          gf_fuse_mount (md->mountpoint, md->fsname, md->mountflags,
                         md->mnt_param, md->status_fd);
        if (md->private->fuse == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_DEBUG, "mount failed (%s)",
                        md->mountpoint);
        }
        gf_log ("glusterfs-fuse", GF_LOG_TRACE, "mount process exited.");

        FREE (data);
        return NULL;
}
/*
struct fuse_operations winfsp_operations = {
        .getattr        = winfsp_getattr,
        .getdir         = winfsp_getdir,
        .readlink       = winfsp_readlink,
        .mknod          = winfsp_mknod,
        .mkdir          = winfsp_mkdir,
        .unlink         = winfsp_unlink,
        .rmdir          = winfsp_rmdir,
        .symlink        = winfsp_symlink,
        .rename         = winfsp_rename,
        .link           = winfsp_link,
        .chmod          = winfsp_chmod,
        .chown          = winfsp_chown,
        .truncate       = winfsp_truncate,
        .utime          = NULL,
        .open           = winfsp_open,
        .read           = winfsp_read,
        .write          = winfsp_write,
        .statfs         = winfsp_statfs,
        .flush          = winfsp_flush,
        .release        = winfsp_release,
        .fsync          = winfsp_fsync,
        .setxattr       = winfsp_setxattr,
        .getxattr       = winfsp_getxattr,
        .listxattr      = winfsp_listxattr,
        .removexattr    = winfsp_removexattr,
        .opendir        = winfsp_opendir,
        .readdir        = winfsp_readdirp,
        .releasedir     = winfsp_releasedir,
        .fsyncdir       = winfsp_fsyncdir,
        .init           = winfsp_init,
        .destroy        = winfsp_destroy,
        .access         = winfsp_access,
        .create         = winfsp_create,
        .ftruncate      = winfsp_ftruncate,
        .fgetattr       = winfsp_fgetattr,
        .lock           = winfsp_lock,
        .utimens        = winfsp_utimens,
        .bmap           = NULL,
};
*/

int cache_getdir (const char* path, fuse_dirh_t h, fuse_dirfil_t filler);

int winfsp_getdir (const char* path, fuse_cache_dirh_t buf,
                   fuse_cache_dirfil_t filler);

struct fuse_cache_operations winfsp_oper = {
        .oper =
          {
            .getattr = winfsp_getattr,
            // .getdir         = winfsp_getdir,
            .readlink = winfsp_readlink,
            .mknod = winfsp_mknod,
            .mkdir = winfsp_mkdir,
            .unlink = winfsp_unlink,
            .rmdir = winfsp_rmdir,
            .symlink = winfsp_symlink,
            .rename = winfsp_rename,
            .link = winfsp_link,
            .chmod = winfsp_chmod,
            .chown = winfsp_chown,
            .truncate = winfsp_truncate,
            .utime = NULL,
            .open = winfsp_open,
            .read = winfsp_read,
            .write = winfsp_write,
            .statfs = winfsp_statfs,
            .flush = winfsp_flush,
            .release = winfsp_release,
            .fsync = winfsp_fsync,
            .setxattr = winfsp_setxattr,
            .getxattr = winfsp_getxattr,
            .listxattr = winfsp_listxattr,
            .removexattr = winfsp_removexattr,
            .opendir = winfsp_opendir,
            // .readdir        = winfsp_readdirp,
            .releasedir = winfsp_releasedir,
            .fsyncdir = winfsp_fsyncdir,
            .init = winfsp_init,
            .destroy = winfsp_destroy,
            .access = winfsp_access,
            .create = winfsp_create,
            .ftruncate = winfsp_ftruncate,
            .fgetattr = winfsp_fgetattr,
            .lock = winfsp_lock,
            .utimens = winfsp_utimens,
            .bmap = NULL,

#if FUSE_VERSION >= 29
            .flag_nullpath_ok = 1,
            .flag_nopath = 1,
#endif
          },
        .cache_getdir = winfsp_getdir,
};
