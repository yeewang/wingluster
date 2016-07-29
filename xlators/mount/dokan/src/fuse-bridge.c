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

#ifdef __NetBSD__
#undef open /* in perfuse.h, pulled from mount-gluster-compat.h */
#endif

static xlator_t *gf_fuse_this_xl = NULL;

static int gf_fuse_conn_err_log;
static int gf_fuse_xattr_enotsup_log;

void fini (xlator_t *this_xl);

static void *
mount_proc(void *data);

static void set_fuse_xlator(xlator_t *this_xl)
{
        gf_fuse_this_xl = this_xl;
}

xlator_t *get_fuse_xlator()
{
        return gf_fuse_this_xl;
}

#ifdef NEVER
static void fuse_invalidate_inode(xlator_t *this, uint64_t fuse_ino);

/*
 * Send an invalidate notification up to fuse to purge the file from local
 * page cache.
 */
static int32_t
fuse_invalidate(xlator_t *this, inode_t *inode)
{

        fuse_private_t *priv = this->private;
        uint64_t nodeid;

        /*
         * NOTE: We only invalidate at the moment if fopen_keep_cache is
         * enabled because otherwise this is a departure from default
         * behavior. Specifically, the performance/write-behind xlator
         * causes unconditional invalidations on write requests.
         */
        if (!priv->fopen_keep_cache)
                return 0;

        nodeid = inode_to_fuse_nodeid(inode);
        gf_log(this->name, GF_LOG_DEBUG, "Invalidate inode id %"GF_PRI_INODE"." , nodeid);
        fuse_log_eh (this, "Sending invalidate inode id: %"GF_PRI_INODE" gfid: %s", nodeid,
                     uuid_utoa (inode->gfid));
        fuse_invalidate_inode(this, nodeid);


        return 0;
}
#endif /* NEVER */

static int32_t
fuse_forget_cbk (xlator_t *this, inode_t *inode)
{
        //Nothing to free in inode ctx, hence return.
        return 0;
}

fuse_fd_ctx_t *
__fuse_fd_ctx_check_n_create (xlator_t *this, fd_t *fd)
{
        uint64_t       val    = 0;
        int32_t        ret    = 0;
        fuse_fd_ctx_t *fd_ctx = NULL;

        ret = __fd_ctx_get (fd, this, &val);

        fd_ctx = (fuse_fd_ctx_t *)(unsigned long) val;

        if (fd_ctx == NULL) {
                fd_ctx = GF_CALLOC (1, sizeof (*fd_ctx),
                                    gf_fuse_mt_fd_ctx_t);
                if (!fd_ctx) {
                    goto out;
                }
                ret = __fd_ctx_set (fd, this,
                                    (uint64_t)(unsigned long)fd_ctx);
                if (ret < 0) {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "fd-ctx-set failed");
                        GF_FREE (fd_ctx);
                        fd_ctx = NULL;
                }
        }
out:
        return fd_ctx;
}

fuse_fd_ctx_t *
fuse_fd_ctx_check_n_create (xlator_t *this, fd_t *fd)
{
        fuse_fd_ctx_t *fd_ctx = NULL;

        if ((fd == NULL) || (this == NULL)) {
                goto out;
        }

        LOCK (&fd->lock);
        {
                fd_ctx = __fuse_fd_ctx_check_n_create (this, fd);
        }
        UNLOCK (&fd->lock);

out:
        return fd_ctx;
}

fuse_fd_ctx_t *
fuse_fd_ctx_get (xlator_t *this, fd_t *fd)
{
        fuse_fd_ctx_t *fdctx = NULL;
        uint64_t       value = 0;
        int            ret   = 0;

        ret = fd_ctx_get (fd, this, &value);
        if (ret < 0) {
                goto out;
        }

        fdctx = (fuse_fd_ctx_t *) (unsigned long)value;

out:
        return fdctx;
}

/*
 * iov_out should contain a fuse_out_header at zeroth position.
 * The error value of this header is sent to kernel.
 */
static int
send_fuse_iov (xlator_t *this, fuse_in_header_t *finh, struct iovec *iov_out,
               int count)
{
#ifdef NEVER
        fuse_private_t *priv = NULL;
        struct fuse_out_header *fouh = NULL;
        int res, i;

        if (!this || !finh || !iov_out) {
                gf_log ("send_fuse_iov", GF_LOG_ERROR,"Invalid arguments");
                return EINVAL;
        }
        priv = this->private;

        fouh = iov_out[0].iov_base;
        iov_out[0].iov_len = sizeof (*fouh);
        fouh->len = 0;
        for (i = 0; i < count; i++)
                fouh->len += iov_out[i].iov_len;
        fouh->unique = finh->unique;

        res = writev (priv->fd, iov_out, count);
        gf_log ("glusterfs-fuse", GF_LOG_TRACE, "writev() result %d/%d %s",
                res, fouh->len, res == -1 ? strerror (errno) : "");

        if (res == -1)
                return errno;
        if (res != fouh->len)
                return EINVAL;

        if (priv->fuse_dump_fd != -1) {
                char w = 'W';

                pthread_mutex_lock (&priv->fuse_dump_mutex);
                res = write (priv->fuse_dump_fd, &w, 1);
                if (res != -1)
                        res = writev (priv->fuse_dump_fd, iov_out, count);
                pthread_mutex_unlock (&priv->fuse_dump_mutex);

                if (res == -1)
                        gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                "failed to dump fuse message (W): %s",
                                strerror (errno));
        }
#endif /* NEVER */

        return 0;
}

static int
send_fuse_data (xlator_t *this, fuse_in_header_t *finh, void *data, size_t size)
{
        struct fuse_out_header fouh = {0, };
        struct iovec iov_out[2];
        int ret = 0;

        fouh.error = 0;
        iov_out[0].iov_base = &fouh;
        iov_out[1].iov_base = data;
        iov_out[1].iov_len = size;

        ret = send_fuse_iov (this, finh, iov_out, 2);
        if (ret != 0)
                gf_log ("glusterfs-fuse", GF_LOG_ERROR, "send_fuse_iov() "
                        "failed: %s", strerror (ret));

        return ret;
}

#define send_fuse_obj(this, finh, obj) \
        send_fuse_data (this, finh, obj, sizeof (*(obj)))


#if FUSE_KERNEL_MINOR_VERSION >= 11
static void
fuse_invalidate_entry (xlator_t *this, uint64_t fuse_ino)
{
        struct fuse_out_header             *fouh   = NULL;
        struct fuse_notify_inval_entry_out *fnieo  = NULL;
        fuse_private_t                     *priv   = NULL;
        dentry_t                           *dentry = NULL;
        inode_t                            *inode  = NULL;
        size_t                              nlen   = 0;
        fuse_invalidate_node_t             *node   = NULL;

        priv = this->private;

        if (!priv->reverse_fuse_thread_started)
                return;

        inode = fuse_ino_to_inode(fuse_ino, this);
        if (inode == NULL) {
                return;
        }

        list_for_each_entry (dentry, &inode->dentry_list, inode_list) {
                node = GF_CALLOC (1, sizeof (*node),
                                  gf_fuse_mt_invalidate_node_t);
                if (node == NULL)
                        break;

                INIT_LIST_HEAD (&node->next);

                fouh  = (struct fuse_out_header *)node->inval_buf;
                fnieo = (struct fuse_notify_inval_entry_out *)(fouh + 1);

                fouh->unique = 0;
                fouh->error = FUSE_NOTIFY_INVAL_ENTRY;

                nlen = strlen (dentry->name);
                fouh->len = sizeof (*fouh) + sizeof (*fnieo) + nlen + 1;
                fnieo->parent = inode_to_fuse_nodeid (dentry->parent);

                fnieo->namelen = nlen;
                strcpy (node->inval_buf + sizeof (*fouh) + sizeof (*fnieo),
                        dentry->name);

                pthread_mutex_lock (&priv->invalidate_mutex);
                {
                        list_add_tail (&node->next, &priv->invalidate_list);
                        pthread_cond_signal (&priv->invalidate_cond);
                }
                pthread_mutex_unlock (&priv->invalidate_mutex);

                gf_log ("glusterfs-fuse", GF_LOG_TRACE, "INVALIDATE entry: "
                        "%"PRIu64"/%s", fnieo->parent, dentry->name);

                if (dentry->parent) {
                        fuse_log_eh (this, "Invalidated entry %s (parent: %s)",
                                     dentry->name,
                                     uuid_utoa (dentry->parent->gfid));
                } else {
                        fuse_log_eh (this, "Invalidated entry %s(nodeid: %" PRIu64 ")",
                                     dentry->name, fnieo->parent);
                }
        }

        if (inode)
                inode_unref (inode);
}
#endif

/*
 * Send an inval inode notification to fuse. This causes an invalidation of the
 * entire page cache mapping on the inode.
 */
static void
fuse_invalidate_inode(xlator_t *this, uint64_t fuse_ino)
{
#if FUSE_KERNEL_MINOR_VERSION >= 11
        struct fuse_out_header *fouh = NULL;
        struct fuse_notify_inval_inode_out *fniio = NULL;
        fuse_private_t *priv = NULL;
        fuse_invalidate_node_t *node = NULL;
        inode_t    *inode = NULL;

        priv = this->private;

        if (!priv->reverse_fuse_thread_started)
                return;

        node = GF_CALLOC (1, sizeof (*node), gf_fuse_mt_invalidate_node_t);
        if (node == NULL)
                return;

        INIT_LIST_HEAD (&node->next);

        fouh = (struct fuse_out_header *) node->inval_buf;
        fniio = (struct fuse_notify_inval_inode_out *) (fouh + 1);

        fouh->unique = 0;
        fouh->error = FUSE_NOTIFY_INVAL_INODE;
        fouh->len = sizeof(struct fuse_out_header) +
                sizeof(struct fuse_notify_inval_inode_out);

        /* inval the entire mapping until we learn how to be more granular */
        fniio->ino = fuse_ino;
        fniio->off = 0;
        fniio->len = -1;

        inode = fuse_ino_to_inode (fuse_ino, this);

        pthread_mutex_lock (&priv->invalidate_mutex);
        {
                list_add_tail (&node->next, &priv->invalidate_list);
                pthread_cond_signal (&priv->invalidate_cond);
        }
        pthread_mutex_unlock (&priv->invalidate_mutex);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE, "INVALIDATE inode: %" PRIu64,
                fuse_ino);

        if (inode) {
                fuse_log_eh (this, "Invalidated inode %" PRIu64 " (gfid: %s)",
                             fuse_ino, uuid_utoa (inode->gfid));
        } else {
                fuse_log_eh (this, "Invalidated inode %" PRIu64, fuse_ino);
        }

        if (inode)
                inode_unref (inode);
#else
	gf_log ("glusterfs-fuse", GF_LOG_WARNING,
		"fuse_invalidate_inode not implemented on OS X due to missing FUSE notification");
#endif
}


int
send_fuse_err (xlator_t *this, fuse_in_header_t *finh, int error)
{
#ifdef NEVER
        struct fuse_out_header fouh = {0, };
        struct iovec iov_out;
        inode_t  *inode = NULL;

        if (error == ESTALE)
                error = ENOENT;

        fouh.error = -error;
        iov_out.iov_base = &fouh;

        inode = fuse_ino_to_inode (finh->nodeid, this);

        // filter out ENOENT
        if (error != ENOENT) {
                if (inode) {
                        fuse_log_eh (this,"Sending %s for operation %d on "
                                     "inode %s", strerror (error), finh->opcode,
                                     uuid_utoa (inode->gfid));
                } else {
                        fuse_log_eh (this, "Sending %s for operation %d on "
                                     "inode %" GF_PRI_INODE,  strerror (error),
                                     finh->opcode, finh->nodeid);
                }
        }

        if (inode)
                inode_unref (inode);


        return send_fuse_iov (this, finh, &iov_out, 1);
#endif /* NEVER */
        return 0;
}

static int
fuse_entry_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno,
                inode_t *inode, struct iatt *buf, dict_t *xdata)
{
        fuse_state_t          *state        = NULL;
        fuse_in_header_t      *finh         = NULL;
        struct fuse_entry_out  feo          = {0, };
        fuse_private_t        *priv         = NULL;
        inode_t               *linked_inode = NULL;
        uint64_t               ctx_value    = LOOKUP_NOT_NEEDED;

        priv = this->private;
        state = frame->root->state;
        finh = state->finh;

        if (op_ret == 0) {
                if (__is_root_gfid (state->loc.inode->gfid))
                        buf->ia_ino = 1;
                if (gf_uuid_is_null (buf->ia_gfid)) {
                        /* With a NULL gfid inode linking is
                           not possible. Let's not pretend this
                           call was a "success".
                        */
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "Received NULL gfid for %s. Forcing EIO",
                                state->loc.path);
                        op_ret = -1;
                        op_errno = EIO;
                }
        }

        /* log into the event-history after the null uuid check is done, since
         * the op_ret and op_errno are being changed if the gfid is NULL.
         */
        fuse_log_eh (this, "op_ret: %d op_errno: %d "
                     "%"PRIu64": %s() %s => %s", op_ret, op_errno,
                     frame->root->unique, gf_fop_list[frame->root->op],
                     state->loc.path, (op_ret == 0)?
                     uuid_utoa(buf->ia_gfid):uuid_utoa(state->loc.gfid));

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %"PRIu64,
                        frame->root->unique, gf_fop_list[frame->root->op],
                        state->loc.path, buf->ia_ino);

                buf->ia_blksize = this->ctx->page_size;
                gf_fuse_stat2attr (buf, &feo.attr, priv->enable_ino32);

                if (!buf->ia_ino) {
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "%"PRIu64": %s() %s returning inode 0",
                                frame->root->unique,
                                gf_fop_list[frame->root->op], state->loc.path);
                }

                linked_inode = inode_link (inode, state->loc.parent,
                                           state->loc.name, buf);

                if (linked_inode == inode) {
                        inode_ctx_set (linked_inode, this, &ctx_value);
                }

                inode_lookup (linked_inode);

                feo.nodeid = inode_to_fuse_nodeid (linked_inode);

                inode_unref (linked_inode);

                feo.entry_valid =
                        calc_timeout_sec (priv->entry_timeout);
                feo.entry_valid_nsec =
                        calc_timeout_nsec (priv->entry_timeout);
                feo.attr_valid =
                        calc_timeout_sec (priv->attribute_timeout);
                feo.attr_valid_nsec =
                        calc_timeout_nsec (priv->attribute_timeout);

#if FUSE_KERNEL_MINOR_VERSION >= 9
                priv->proto_minor >= 9 ?
                send_fuse_obj (this, finh, &feo) :
                send_fuse_data (this, finh, &feo,
                                FUSE_COMPAT_ENTRY_OUT_SIZE);
#else
                send_fuse_obj (this, finh, &feo);
#endif
        } else {
                gf_log ("glusterfs-fuse",
                        (op_errno == ENOENT ? GF_LOG_TRACE : GF_LOG_WARNING),
                        "%"PRIu64": %s() %s => -1 (%s)", frame->root->unique,
                        gf_fop_list[frame->root->op], state->loc.path,
                        strerror (op_errno));

		if ((op_errno == ENOENT) && (priv->negative_timeout != 0)) {
			feo.entry_valid =
				calc_timeout_sec (priv->negative_timeout);
			feo.entry_valid_nsec =
				calc_timeout_nsec (priv->negative_timeout);
			send_fuse_obj (this, finh, &feo);
		} else {
			send_fuse_err (this, state->finh, op_errno);
                }
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);
        return 0;
}

static int
fuse_newentry_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno,
                   inode_t *inode, struct iatt *buf, struct iatt *preparent,
                   struct iatt *postparent, dict_t *xdata)
{
        fuse_entry_cbk (frame, cookie, this, op_ret, op_errno, inode, buf,
                        xdata);
        return 0;
}

static int
fuse_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno,
                 inode_t *inode, struct iatt *stat, dict_t *dict,
                 struct iatt *postparent)
{
        fuse_state_t            *state = NULL;
        call_frame_t            *prev = NULL;
        inode_table_t           *itable = NULL;

        state = frame->root->state;
        prev  = cookie;

        if (op_ret == -1 && state->is_revalidate == 1) {
                itable = state->itable;
		/*
		 * A stale mapping might exist for a dentry/inode that has been
		 * removed from another client.
		 */
		if (op_errno == ENOENT)
			inode_unlink(state->loc.inode, state->loc.parent,
				     state->loc.name);
                inode_unref (state->loc.inode);
                state->loc.inode = inode_new (itable);
                state->is_revalidate = 2;
                if (gf_uuid_is_null (state->gfid))
                        gf_uuid_generate (state->gfid);
                fuse_gfid_set (state);

                STACK_WIND (frame, fuse_lookup_cbk,
                            prev->this, prev->this->fops->lookup,
                            &state->loc, state->xdata);
                return 0;
        }

        fuse_entry_cbk (frame, cookie, this, op_ret, op_errno, inode, stat,
                        dict);
        return 0;
}

void
fuse_fop_resume (fuse_state_t *state)
{
        fuse_resume_fn_t fn = NULL;

        /*
         * Fail fd resolution failures right away.
         */
        if (state->resolve.fd && state->resolve.op_ret < 0) {
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        fn = state->resume_fn;
        fn (state);
}

void
fuse_lookup_resume (fuse_state_t *state)
{
        if (!state->loc.parent && !state->loc.inode) {
                gf_log ("fuse", GF_LOG_ERROR, "failed to resolve path %s",
                        state->loc.path);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        /* parent was resolved, entry could not, may be a missing gfid?
         * Hence try to do a regular lookup
         */
        if ((state->resolve.op_ret == -1)
            && (state->resolve.op_errno == ENODATA)) {
                state->resolve.op_ret = 0;
        }

        if (state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "LOOKUP %s(%s)",
                        state->loc.path, uuid_utoa (state->loc.inode->gfid));
                state->is_revalidate = 1;
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "LOOKUP %s",
                        state->loc.path);
                state->loc.inode = inode_new (state->loc.parent->table);
                if (gf_uuid_is_null (state->gfid))
                        gf_uuid_generate (state->gfid);
                fuse_gfid_set (state);
        }

        FUSE_FOP (state, fuse_lookup_cbk, GF_FOP_LOOKUP,
                  lookup, &state->loc, state->xdata);
}

static void
fuse_lookup (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        char           *name     = msg;
        fuse_state_t   *state    = NULL;

        GET_STATE (this, finh, state);

        (void) fuse_resolve_entry_init (state, &state->resolve,
                                        1, name);

        fuse_resolve_and_resume (state, fuse_lookup_resume);

        return;
}

static void
do_forget(xlator_t *this, uint64_t nodeid, uint64_t nlookup)
{
	inode_t *fuse_inode = fuse_ino_to_inode(nodeid, this);

	fuse_log_eh(this, "FORGET %"PRIu64"/%"PRIu64" gfid: (%s)",
		    nodeid, nlookup, uuid_utoa(fuse_inode->gfid));

	inode_forget(fuse_inode, nlookup);
	inode_unref(fuse_inode);
}

static void
fuse_forget (xlator_t *this, fuse_in_header_t *finh, void *msg)

{
        struct fuse_forget_in *ffi        = msg;

#ifdef NEVER
        if (finh->nodeid == 1) {
                GF_FREE (finh);
                return;
        }
#endif /* NEVER */

#ifdef NEVER
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": FORGET %"PRIu64"/%"PRIu64,
                finh->unique, finh->nodeid, ffi->nlookup);
#endif /* NEVER */

	do_forget(this, 1, ffi->nlookup);

        GF_FREE (finh);
}

static int
fuse_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata)
{
        fuse_state_t     *state;
        fuse_in_header_t *finh;
        fuse_private_t   *priv = NULL;
        struct fuse_attr_out fao;

        priv  = this->private;
        state = frame->root->state;
        finh  = state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %"PRIu64, frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR",
                        prebuf->ia_ino);

                postbuf->ia_blksize = this->ctx->page_size;
                gf_fuse_stat2attr (postbuf, &fao.attr, priv->enable_ino32);

                fao.attr_valid = calc_timeout_sec (priv->attribute_timeout);
                fao.attr_valid_nsec =
                  calc_timeout_nsec (priv->attribute_timeout);

#if FUSE_KERNEL_MINOR_VERSION >= 9
                priv->proto_minor >= 9 ?
                send_fuse_obj (this, finh, &fao) :
                send_fuse_data (this, finh, &fao,
                                FUSE_COMPAT_ATTR_OUT_SIZE);
#else
                send_fuse_obj (this, finh, &fao);
#endif
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": %s() %s => -1 (%s)", frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR",
                        strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

static int
fuse_attr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iatt *buf, dict_t *xdata)
{
        fuse_state_t     *state;
        fuse_in_header_t *finh;
        fuse_private_t   *priv = NULL;
        struct fuse_attr_out fao;

        priv  = this->private;
        state = frame->root->state;
        finh  = state->finh;

        fuse_log_eh (this, "op_ret: %d, op_errno: %d, %"PRIu64": %s() %s => "
                   "gfid: %s", op_ret, op_errno, frame->root->unique,
                   gf_fop_list[frame->root->op], state->loc.path,
                   state->loc.inode ? uuid_utoa (state->loc.inode->gfid) : "");
        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %"PRIu64, frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR",
                        buf->ia_ino);

                buf->ia_blksize = this->ctx->page_size;
                gf_fuse_stat2attr (buf, &fao.attr, priv->enable_ino32);

                fao.attr_valid = calc_timeout_sec (priv->attribute_timeout);
                fao.attr_valid_nsec =
                  calc_timeout_nsec (priv->attribute_timeout);

#if FUSE_KERNEL_MINOR_VERSION >= 9
                priv->proto_minor >= 9 ?
                send_fuse_obj (this, finh, &fao) :
                send_fuse_data (this, finh, &fao,
                                FUSE_COMPAT_ATTR_OUT_SIZE);
#else
                send_fuse_obj (this, finh, &fao);
#endif
        } else {
                GF_LOG_OCCASIONALLY ( gf_fuse_conn_err_log, "glusterfs-fuse",
                                      GF_LOG_WARNING,
                                      "%"PRIu64": %s() %s => -1 (%s)",
                                      frame->root->unique,
                                      gf_fop_list[frame->root->op],
                                      state->loc.path ? state->loc.path : "ERR",
                                      strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

static int
fuse_root_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      inode_t *inode, struct iatt *stat, dict_t *dict,
                      struct iatt *postparent)
{
        fuse_attr_cbk (frame, cookie, this, op_ret, op_errno, stat, dict);

        return 0;
}

void
fuse_getattr_resume (fuse_state_t *state)
{
        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "GETATTR (%s) resolution failed",
                        uuid_utoa (state->resolve.gfid));
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        if (!IA_ISDIR (state->loc.inode->ia_type)) {
                state->fd = fd_lookup (state->loc.inode, 0/*state->finh->pid*/);
        }

        if (!state->fd) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "GETATTR (%s)",
                        state->loc.path);

                FUSE_FOP (state, fuse_attr_cbk, GF_FOP_STAT,
                          stat, &state->loc, state->xdata);
        } else {

                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "FGETATTR (%s/%p)",
                        state->loc.path, state->fd);

                FUSE_FOP (state, fuse_attr_cbk, GF_FOP_FSTAT,
                          fstat, state->fd, state->xdata);
        }
}

//static void
//fuse_getattr (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_getattr(const char *path, struct FUSE_STAT *stbuf)
{
        xlator_t *this = get_fuse_xlator();
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();
        __asm__("int $3");

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_GETATTR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        int32_t       ret = -1;

        GET_STATE (this, finh, state);

        state->gfid[15] = 1;

        ret = fuse_loc_fill (&state->loc, state, 1/*finh->nodeid*/, 0, NULL);
        if (ret < 0) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "GETATTR on / (fuse_loc_fill() failed)");
                send_fuse_err (this, finh, ENOENT);
                free_fuse_state (state);
                return;
        }

        fuse_gfid_set (state);

        FUSE_FOP (state, fuse_root_lookup_cbk, GF_FOP_LOOKUP,
                  lookup, &state->loc, state->xdata);
        return;

        fuse_resolve_inode_init (state, &state->resolve, 1/*state->finh->nodeid*/);

        fuse_resolve_and_resume (state, fuse_getattr_resume);
}

static int32_t
fuse_fd_inherit_directio (xlator_t *this, fd_t *fd, struct fuse_open_out *foo)
{
        int32_t        ret    = 0;
        fuse_fd_ctx_t *fdctx  = NULL, *tmp_fdctx = NULL;
        fd_t          *tmp_fd = NULL;

        GF_VALIDATE_OR_GOTO_WITH_ERROR ("glusterfs-fuse", this, out, ret,
                                        -EINVAL);
        GF_VALIDATE_OR_GOTO_WITH_ERROR ("glusterfs-fuse", fd, out, ret,
                                        -EINVAL);
        GF_VALIDATE_OR_GOTO_WITH_ERROR ("glusterfs-fuse", foo, out, ret,
                                        -EINVAL);

        fdctx = fuse_fd_ctx_get (this, fd);
        if (!fdctx) {
                ret = -ENOMEM;
                goto out;
        }

        tmp_fd = fd_lookup (fd->inode, 0);
        if (tmp_fd) {
                tmp_fdctx = fuse_fd_ctx_get (this, tmp_fd);
                if (tmp_fdctx) {
                        foo->open_flags &= ~FOPEN_DIRECT_IO;
                        foo->open_flags |= (tmp_fdctx->open_flags
                                            & FOPEN_DIRECT_IO);
                }
        }

        fdctx->open_flags |= (foo->open_flags & FOPEN_DIRECT_IO);

        if (tmp_fd != NULL) {
                fd_unref (tmp_fd);
        }

        ret = 0;
out:
        return ret;
}


gf_boolean_t
direct_io_mode (dict_t *xdata)
{
	if (xdata && dict_get (xdata, "direct-io-mode"))
		return _gf_true;
	return _gf_false;
}


static int
fuse_fd_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
             int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        fuse_state_t         *state  = NULL;
        fuse_in_header_t     *finh   = NULL;
        fuse_private_t       *priv   = NULL;
        int32_t               ret    = 0;
        struct fuse_open_out  foo    = {0, };

        priv = this->private;
        state = frame->root->state;
        finh = state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret >= 0) {
                foo.fh = (uintptr_t) fd;
                foo.open_flags = 0;

                if (!IA_ISDIR (fd->inode->ia_type)) {
                        if (((priv->direct_io_mode == 2)
                             && ((state->flags & O_ACCMODE) != O_RDONLY))
                            || (priv->direct_io_mode == 1)
			    || (direct_io_mode (xdata)))
                                foo.open_flags |= FOPEN_DIRECT_IO;
#ifdef GF_DARWIN_HOST_OS
                        /* In Linux: by default, buffer cache
                         * is purged upon open, setting
                         * FOPEN_KEEP_CACHE implies no-purge
                         *
                         * In MacFUSE: by default, buffer cache
                         * is left intact upon open, setting
                         * FOPEN_PURGE_UBC implies purge
                         *
                         * [[Interesting...]]
                         */
                        if (!priv->fopen_keep_cache)
                                foo.open_flags |= FOPEN_PURGE_UBC;
#else
                        /*
                         * If fopen-keep-cache is enabled, we set the associated
                         * flag here such that files are not invalidated on open.
                         * File invalidations occur either in fuse or explicitly
                         * when the cache is set invalid on the inode.
                         */
                        if (priv->fopen_keep_cache)
                                foo.open_flags |= FOPEN_KEEP_CACHE;
#endif
                }

                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %p", frame->root->unique,
                        gf_fop_list[frame->root->op], state->loc.path, fd);

                ret = fuse_fd_inherit_directio (this, fd, &foo);
                if (ret < 0) {
                        op_errno = -ret;
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "cannot inherit direct-io values for fd "
                                "(ptr:%p inode-gfid:%s) from fds already "
                                "opened", fd, uuid_utoa (fd->inode->gfid));
                        goto err;
                }

                if (send_fuse_obj (this, finh, &foo) == ENOENT) {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "open(%s) got EINTR", state->loc.path);
                        gf_fd_put (priv->fdtable, state->fd_no);
                        goto out;
                }

                fd_bind (fd);
        } else {
        err:
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": %s() %s => -1 (%s)", frame->root->unique,
                        gf_fop_list[frame->root->op], state->loc.path,
                        strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
                gf_fd_put (priv->fdtable, state->fd_no);
        }
out:
        free_fuse_state (state);
        STACK_DESTROY (frame->root);
        return 0;
}

static void
fuse_do_truncate (fuse_state_t *state)
{
        if (state->fd) {
                FUSE_FOP (state, fuse_truncate_cbk, GF_FOP_FTRUNCATE,
                          ftruncate, state->fd, state->off, state->xdata);
        } else {
                FUSE_FOP (state, fuse_truncate_cbk, GF_FOP_TRUNCATE,
                          truncate, &state->loc, state->off, state->xdata);
        }

        return;
}

static int
fuse_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno,
                  struct iatt *statpre, struct iatt *statpost, dict_t *xdata)
{
        fuse_state_t     *state;
        fuse_in_header_t *finh;
        fuse_private_t   *priv = NULL;
        struct fuse_attr_out fao;

        int op_done = 0;

        priv  = this->private;
        state = frame->root->state;
        finh  = state->finh;

        fuse_log_eh(this, "op_ret: %d, op_errno: %d, %"PRIu64", %s() %s => "
                    "gfid: %s", op_ret, op_errno, frame->root->unique,
                    gf_fop_list[frame->root->op], state->loc.path,
                    state->loc.inode ? uuid_utoa (state->loc.inode->gfid) : "");

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %"PRIu64, frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR",
                        statpost->ia_ino);

                statpost->ia_blksize = this->ctx->page_size;
                gf_fuse_stat2attr (statpost, &fao.attr, priv->enable_ino32);

                fao.attr_valid = calc_timeout_sec (priv->attribute_timeout);
                fao.attr_valid_nsec =
                        calc_timeout_nsec (priv->attribute_timeout);

                if (state->truncate_needed) {
                        fuse_do_truncate (state);
                } else {
#if FUSE_KERNEL_MINOR_VERSION >= 9
                        priv->proto_minor >= 9 ?
                        send_fuse_obj (this, finh, &fao) :
                        send_fuse_data (this, finh, &fao,
                                        FUSE_COMPAT_ATTR_OUT_SIZE);
#else
                        send_fuse_obj (this, finh, &fao);
#endif
                        op_done = 1;
                }
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": %s() %s => -1 (%s)", frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR",
                        strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
                op_done = 1;
        }

        if (op_done) {
                free_fuse_state (state);
        }

        STACK_DESTROY (frame->root);

        return 0;
}

static int32_t
fattr_to_gf_set_attr (int32_t valid)
{
        int32_t gf_valid = 0;

        if (valid & FATTR_MODE)
                gf_valid |= GF_SET_ATTR_MODE;

        if (valid & FATTR_UID)
                gf_valid |= GF_SET_ATTR_UID;

        if (valid & FATTR_GID)
                gf_valid |= GF_SET_ATTR_GID;

        if (valid & FATTR_ATIME)
                gf_valid |= GF_SET_ATTR_ATIME;

        if (valid & FATTR_MTIME)
                gf_valid |= GF_SET_ATTR_MTIME;

        if (valid & FATTR_SIZE)
                gf_valid |= GF_SET_ATTR_SIZE;

        return gf_valid;
}

#define FATTR_MASK   (FATTR_SIZE                        \
                      | FATTR_UID | FATTR_GID           \
                      | FATTR_ATIME | FATTR_MTIME       \
                      | FATTR_MODE)

void
fuse_setattr_resume (fuse_state_t *state)
{
        if (!state->fd && !state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "SETATTR (%s) resolution failed",
                        uuid_utoa (state->resolve.gfid));
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "SETATTR %s", state->loc.path);

#ifdef GF_TEST_FFOP
        /* this is for calls like 'fchmod()' */
        if (!state->fd)
                state->fd = fd_lookup (state->loc.inode, state->finh->pid);
#endif /* GF_TEST_FFOP */

        if ((state->valid & (FATTR_MASK)) != FATTR_SIZE) {
                if (state->fd &&
                    !((state->valid & FATTR_ATIME) ||
                      (state->valid & FATTR_MTIME))) {
                        /*
                            there is no "futimes" call, so don't send
                            fsetattr if ATIME or MTIME is set
                         */

                        FUSE_FOP (state, fuse_setattr_cbk, GF_FOP_FSETATTR,
                                  fsetattr, state->fd, &state->attr,
                                  fattr_to_gf_set_attr (state->valid),
                                  state->xdata);
                } else {
                        FUSE_FOP (state, fuse_setattr_cbk, GF_FOP_SETATTR,
                                  setattr, &state->loc, &state->attr,
                                  fattr_to_gf_set_attr (state->valid),
                                  state->xdata);
                }
        } else {
                fuse_do_truncate (state);
        }

}

static void
fuse_setattr (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        struct fuse_setattr_in *fsi = msg;

#if FUSE_KERNEL_MINOR_VERSION >= 9
        fuse_private_t  *priv = NULL;
#endif
        fuse_state_t *state = NULL;

        GET_STATE (this, finh, state);

        if (fsi->valid & FATTR_FH &&
            !(fsi->valid & (FATTR_ATIME|FATTR_MTIME))) {
                /* We need no loc if kernel sent us an fd and
                 * we are not fiddling with times */
                state->fd = FH_TO_FD (fsi->fh);
                fuse_resolve_fd_init (state, &state->resolve, state->fd);
        } else {
                fuse_resolve_inode_init (state, &state->resolve, 1/*finh->nodeid*/);
        }

        /*
         * This is just stub code demonstrating how to retrieve
         * lock_owner in setattr, according to the FUSE proto.
         * We do not make use of ATM. Its purpose is supporting
         * mandatory locking, but getting that right is further
         * down the road. Cf.
         *
         * http://thread.gmane.org/gmane.comp.file-systems.fuse.devel/
         * 4962/focus=4982
         *
         * http://git.kernel.org/?p=linux/kernel/git/torvalds/
         * linux-2.6.git;a=commit;h=v2.6.23-5896-gf333211
         */
#if FUSE_KERNEL_MINOR_VERSION >= 9
        priv = this->private;
        if (priv->proto_minor >= 9 && fsi->valid & FATTR_LOCKOWNER)
                state->lk_owner = fsi->lock_owner;
#endif

        state->valid = fsi->valid;

        if ((fsi->valid & (FATTR_MASK)) != FATTR_SIZE) {
                if (fsi->valid & FATTR_SIZE) {
                        state->off             = fsi->size;
                        state->truncate_needed = _gf_true;
                }

                state->attr.ia_size  = fsi->size;
                state->attr.ia_atime = fsi->atime;
                state->attr.ia_mtime = fsi->mtime;
                state->attr.ia_atime_nsec = fsi->atimensec;
                state->attr.ia_mtime_nsec = fsi->mtimensec;

                state->attr.ia_prot = ia_prot_from_st_mode (fsi->mode);
                state->attr.ia_uid  = fsi->uid;
                state->attr.ia_gid  = fsi->gid;
        } else {
                state->off = fsi->size;
        }

        fuse_resolve_and_resume (state, fuse_setattr_resume);
}

static int
fuse_removexattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        fuse_state_t *state = NULL;
        fuse_in_header_t *finh = NULL;

        GF_ASSERT (frame);
        GF_ASSERT (frame->root);

        state =  frame->root->state;
        finh  =  state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => 0", frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR");

                send_fuse_err (this, finh, 0);
        } else {
                gf_log ("glusterfs-fuse",
                        (ENODATA == op_errno) ? GF_LOG_DEBUG : GF_LOG_WARNING,
                        "%"PRIu64": %s() of %s on %s => -1 (%s)",
                        frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->name ? state->name : "",
                        state->loc.path ? state->loc.path : "ERR",
                        strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

static int
fuse_err_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
              int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        fuse_state_t *state = frame->root->state;
        fuse_in_header_t *finh = state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => 0", frame->root->unique,
                        gf_fop_list[frame->root->op],
                        state->loc.path ? state->loc.path : "ERR");

                send_fuse_err (this, finh, 0);
        } else {
                if (GF_IGNORE_IF_GSYNCD_SAFE_ERROR(frame, op_errno)) {
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "%"PRIu64": %s() %s => -1 (%s)",
                                frame->root->unique,
                                gf_fop_list[frame->root->op],
                                state->loc.path ? state->loc.path : "ERR",
                                strerror (op_errno));
                }

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

static int
fuse_fsync_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                struct iatt *postbuf, dict_t *xdata)
{
        return fuse_err_cbk (frame, cookie, this, op_ret, op_errno, xdata);
}

static int
fuse_setxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        if (op_ret == -1 && op_errno == ENOTSUP)
                GF_LOG_OCCASIONALLY (gf_fuse_xattr_enotsup_log,
                                     "glusterfs-fuse", GF_LOG_CRITICAL,
                                     "extended attribute not supported "
                                     "by the backend storage");

        return fuse_err_cbk (frame, cookie, this, op_ret, op_errno, xdata);
}

static int
fuse_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, struct iatt *preparent,
                 struct iatt *postparent, dict_t *xdata)
{
        fuse_state_t     *state = NULL;
        fuse_in_header_t *finh = NULL;

        state = frame->root->state;
        finh = state->finh;

        fuse_log_eh (this, "op_ret: %d, op_errno: %d, %"PRIu64": %s() %s => "
                     "gfid: %s", op_ret, op_errno, frame->root->unique,
                     gf_fop_list[frame->root->op], state->loc.path,
                     state->loc.inode ? uuid_utoa (state->loc.inode->gfid) : "");

        if (op_ret == 0) {
                inode_unlink (state->loc.inode, state->loc.parent,
                              state->loc.name);
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => 0", frame->root->unique,
                        gf_fop_list[frame->root->op], state->loc.path);

                send_fuse_err (this, finh, 0);
        } else {
                if (GF_IGNORE_IF_GSYNCD_SAFE_ERROR(frame, op_errno)) {
                        gf_log ("glusterfs-fuse",
                                op_errno == ENOTEMPTY ? GF_LOG_DEBUG :
                                GF_LOG_WARNING, "%"PRIu64": %s() %s => -1 (%s)",
                                frame->root->unique,
                                gf_fop_list[frame->root->op], state->loc.path,
                                strerror (op_errno));
                }
                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

void
fuse_access_resume (fuse_state_t *state)
{
        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "%"PRIu64": ACCESS %"PRIu64" (%s) resolution failed",
                        state->finh->unique, state->finh->nodeid,
                        uuid_utoa (state->resolve.gfid));
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64" ACCESS %s/%"PRIu64" mask=%d",
                state->finh->unique, state->loc.path,
                state->finh->nodeid, state->mask);

        FUSE_FOP (state, fuse_err_cbk, GF_FOP_ACCESS, access,
                  &state->loc, state->mask, state->xdata);
}

//static void
//fuse_access (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_access(const char *path, int mask)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_access => %s", path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_OPEN;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        GET_STATE (this, finh, state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        state->mask = mask;

        fuse_resolve_and_resume (state, fuse_access_resume);

        return;
}

static int
fuse_readlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, const char *linkname,
                   struct iatt *buf, dict_t *xdata)
{
        fuse_state_t     *state = NULL;
        fuse_in_header_t *finh = NULL;

        state = frame->root->state;
        finh = state->finh;

        fuse_log_eh (this, "op_ret: %d, op_errno: %d %"PRIu64": %s() => %s"
                     " linkname: %s, gfid: %s", op_ret, op_errno,
                     frame->root->unique, gf_fop_list[frame->root->op],
                     state->loc.gfid, linkname,
                     uuid_utoa (state->loc.gfid));

        if (op_ret > 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s => %s (size:%d)", frame->root->unique,
                        state->loc.path, linkname, op_ret);
                send_fuse_data (this, finh, (void *)linkname, op_ret);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": %s => -1 (%s)", frame->root->unique,
                        state->loc.path, strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

void
fuse_readlink_resume (fuse_state_t *state)
{
        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "READLINK %"PRIu64" (%s) resolution failed",
                        state->finh->unique, uuid_utoa (state->resolve.gfid));
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64" READLINK %s/%s", state->finh->unique,
                state->loc.path, uuid_utoa (state->loc.inode->gfid));

        FUSE_FOP (state, fuse_readlink_cbk, GF_FOP_READLINK,
                  readlink, &state->loc, 4096, state->xdata);
}

// static void
// fuse_readlink (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_readlink (const char *path, char *buf, size_t size)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_readlink => %s", path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_READLINK;
        finh->unique = 0;
        finh->nodeid = 1;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        GET_STATE (this, finh, state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        fuse_resolve_and_resume (state, fuse_readlink_resume);

        return;
}

void
fuse_mknod_resume (fuse_state_t *state)
{
        if (!state->loc.parent) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "MKNOD %"PRIu64"/%s (%s/%s) resolution failed",
                        state->finh->nodeid, state->resolve.bname,
                        uuid_utoa (state->resolve.gfid), state->resolve.bname);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        if (state->resolve.op_errno == ENOENT) {
                state->resolve.op_ret = 0;
                state->resolve.op_errno = 0;
        }

        if (state->loc.inode) {
                gf_log (state->this->name, GF_LOG_DEBUG, "inode already present");
                inode_unref (state->loc.inode);
                state->loc.inode = NULL;
        }

        state->loc.inode = inode_new (state->loc.parent->table);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": MKNOD %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_newentry_cbk, GF_FOP_MKNOD,
                  mknod, &state->loc, state->mode, state->rdev, state->umask,
                  state->xdata);
}

// static void
// fuse_mknod (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_mknod (const char *path, mode_t mode, dev_t rdev)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_mknod => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_mknod_in fmi;

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKNOD;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fmi.mode = mode;
        fmi.rdev = rdev;

        char *name = (char *)(path);

#if FUSE_KERNEL_MINOR_VERSION >= 12
        fuse_private_t *priv = NULL;
        int32_t         ret = -1;
#endif

        GET_STATE (this, finh, state);

        gf_uuid_generate (state->gfid);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, name);

        state->mode = mode;
        state->rdev = rdev;

#if FUSE_KERNEL_MINOR_VERSION >=12
        priv = this->private;
        FUSE_ENTRY_CREATE(this, priv, finh, state, (&fmi), "MKNOD");
#endif

        fuse_resolve_and_resume (state, fuse_mknod_resume);

        return;
}

void
fuse_mkdir_resume (fuse_state_t *state)
{
        if (!state->loc.parent) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "MKDIR %"PRIu64" (%s/%s) resolution failed",
                        state->finh->nodeid, uuid_utoa (state->resolve.gfid),
                        state->resolve.bname);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        if (state->resolve.op_errno == ENOENT) {
                state->resolve.op_ret = 0;
                state->resolve.op_errno = 0;
        }

        if (state->loc.inode) {
                gf_log (state->this->name, GF_LOG_DEBUG, "inode already present");
                inode_unref (state->loc.inode);
                state->loc.inode = NULL;
        }

        state->loc.inode = inode_new (state->loc.parent->table);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": MKDIR %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_newentry_cbk, GF_FOP_MKDIR,
                  mkdir, &state->loc, state->mode, state->umask, state->xdata);
}

// static void
// fuse_mkdir (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_mkdir (const char *path, mode_t mode)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_mkdir => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_mkdir_in fmi;

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fmi.mode = mode;

        char *name = (char *)(path);

#if FUSE_KERNEL_MINOR_VERSION >=12
        fuse_private_t *priv = NULL;
        int32_t         ret = -1;
#endif

        GET_STATE (this, finh, state);

        gf_uuid_generate (state->gfid);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, name);

        state->mode = mode;

#if FUSE_KERNEL_MINOR_VERSION >=12
        priv = this->private;
        FUSE_ENTRY_CREATE(this, priv, finh, state, (&fmi), "MKDIR");
#endif

        fuse_resolve_and_resume (state, fuse_mkdir_resume);

        return;
}

void
fuse_unlink_resume (fuse_state_t *state)
{
        if (!state->loc.parent || !state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "UNLINK %"PRIu64" (%s/%s) resolution failed",
                        state->finh->nodeid, uuid_utoa (state->resolve.gfid),
                        state->resolve.bname);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": UNLINK %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_unlink_cbk, GF_FOP_UNLINK,
                  unlink, &state->loc, 0, state->xdata);
}

// static void
// fuse_unlink (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int fuse_unlink (const char *path)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_unlink => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_UNLINK;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        char         *name = path;

        GET_STATE (this, finh, state);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, name);

        fuse_resolve_and_resume (state, fuse_unlink_resume);

        return;
}

void
fuse_rmdir_resume (fuse_state_t *state)
{
        if (!state->loc.parent || !state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "RMDIR %"PRIu64" (%s/%s) resolution failed",
                        state->finh->nodeid, uuid_utoa (state->resolve.gfid),
                        state->resolve.bname);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": RMDIR %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_unlink_cbk, GF_FOP_RMDIR,
                  rmdir, &state->loc, 0, state->xdata);
}

// static void
// fuse_rmdir (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_rmdir(const char *path)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_rmdir => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        char *name = (char *)(path);

        GET_STATE (this, finh, state);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, name);

        fuse_resolve_and_resume (state, fuse_rmdir_resume);

        return;
}

void
fuse_symlink_resume (fuse_state_t *state)
{
        if (!state->loc.parent) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "SYMLINK %"PRIu64" (%s/%s) -> %s resolution failed",
                        state->finh->nodeid, uuid_utoa (state->resolve.gfid),
                        state->resolve.bname, state->name);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        if (state->resolve.op_errno == ENOENT) {
                state->resolve.op_ret = 0;
                state->resolve.op_errno = 0;
        }

        if (state->loc.inode) {
                gf_log (state->this->name, GF_LOG_DEBUG, "inode already present");
                inode_unref (state->loc.inode);
                state->loc.inode = NULL;
        }

        state->loc.inode = inode_new (state->loc.parent->table);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": SYMLINK %s -> %s", state->finh->unique,
                state->loc.path, state->name);

        FUSE_FOP (state, fuse_newentry_cbk, GF_FOP_SYMLINK,
                  symlink, state->name, &state->loc, state->umask, state->xdata);
}

// static void
// fuse_symlink (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int fuse_symlink (const char *from, const char *to)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_symlink => %s",
                from);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_SYMLINK;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), from, 128);

        char         *name = from;
        char         *linkname = to;

        GET_STATE (this, finh, state);

        gf_uuid_generate (state->gfid);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, name);

        state->name = gf_strdup (linkname);

        fuse_resolve_and_resume (state, fuse_symlink_resume);

        return;
}

int
fuse_rename_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, struct iatt *buf,
                 struct iatt *preoldparent, struct iatt *postoldparent,
                 struct iatt *prenewparent, struct iatt *postnewparent,
                 dict_t *xdata)
{
        fuse_state_t     *state = NULL;
        fuse_in_header_t *finh = NULL;

        state = frame->root->state;
        finh  = state->finh;

        fuse_log_eh (this, "op_ret: %d, op_errno: %d, %"PRIu64": %s() "
                     "path: %s parent: %s ==> path: %s parent: %s"
                     "gfid: %s", op_ret, op_errno, frame->root->unique,
                     gf_fop_list[frame->root->op], state->loc.path,
                     state->loc.parent?uuid_utoa (state->loc.parent->gfid):"",
                     state->loc2.path,
                     state->loc2.parent?uuid_utoa (state->loc2.parent->gfid):"",
                     state->loc.inode?uuid_utoa (state->loc.inode->gfid):"");

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s -> %s => 0 (buf->ia_ino=%"PRIu64")",
                        frame->root->unique, state->loc.path, state->loc2.path,
                        buf->ia_ino);

                {
                        /* ugly ugly - to stay blind to situation where
                           rename happens on a new inode
                        */
                        buf->ia_type = state->loc.inode->ia_type;
                }
                buf->ia_blksize = this->ctx->page_size;

                inode_rename (state->loc.parent->table,
                              state->loc.parent, state->loc.name,
                              state->loc2.parent, state->loc2.name,
                              state->loc.inode, buf);

                send_fuse_err (this, finh, 0);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": %s -> %s => -1 (%s)", frame->root->unique,
                        state->loc.path, state->loc2.path,
                        strerror (op_errno));
                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);
        return 0;
}

void
fuse_rename_resume (fuse_state_t *state)
{
        char loc_uuid[64]  = {0,};
        char loc2_uuid[64] = {0,};

        if (!state->loc.parent || !state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "RENAME %"PRIu64" %s/%s -> %s/%s src resolution failed",
                        state->finh->unique,
                        uuid_utoa_r (state->resolve.gfid, loc_uuid),
                        state->resolve.bname,
                        uuid_utoa_r (state->resolve2.gfid, loc2_uuid),
                        state->resolve2.bname);

                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        if (!state->loc2.parent) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "RENAME %"PRIu64" %s/%s -> %s/%s dst resolution failed",
                        state->finh->unique,
                        uuid_utoa_r (state->resolve.gfid, loc_uuid),
                        state->resolve.bname,
                        uuid_utoa_r (state->resolve2.gfid, loc2_uuid),
                        state->resolve2.bname);

                send_fuse_err (state->this, state->finh, ENOENT);
                free_fuse_state (state);
                return;
        }

        state->resolve.op_ret = 0;
        state->resolve2.op_ret = 0;

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": RENAME `%s (%s)' -> `%s (%s)'",
                state->finh->unique, state->loc.path, loc_uuid,
                state->loc2.path, loc2_uuid);

        FUSE_FOP (state, fuse_rename_cbk, GF_FOP_RENAME,
                  rename, &state->loc, &state->loc2, state->xdata);
}

// static void
// fuse_rename (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_rename (const char *from, const char *to)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_rename => %s",
                from);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_rename_in  fri;
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_SYMLINK;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        char *oldname = from;
        char *newname = to;
        fri.newdir = finh->nodeid;

        GET_STATE (this, finh, state);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, oldname);

        fuse_resolve_entry_init (state, &state->resolve2, fri.newdir, newname);

        fuse_resolve_and_resume (state, fuse_rename_resume);

        return;
}

void
fuse_link_resume (fuse_state_t *state)
{
        if (!state->loc2.inode || !state->loc.parent) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "fuse_loc_fill() failed %"PRIu64": LINK %s %s",
                        state->finh->unique, state->loc2.path, state->loc.path);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        state->resolve.op_ret = 0;
        state->resolve2.op_ret = 0;

        if (state->loc.inode) {
                inode_unref (state->loc.inode);
                state->loc.inode = NULL;
        }
        state->loc.inode = inode_ref (state->loc2.inode);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": LINK() %s -> %s",
                state->finh->unique, state->loc2.path,
                state->loc.path);

        FUSE_FOP (state, fuse_newentry_cbk, GF_FOP_LINK,
                  link, &state->loc2, &state->loc, state->xdata);
}

// static void
// fuse_link (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_link (const char *from, const char *to)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_link => %s",
                from);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_link_in fli;
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_SYMLINK;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        GET_STATE (this, finh, state);

        fli.oldnodeid = 1;

        fuse_resolve_entry_init (state, &state->resolve2, fli.oldnodeid, from);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, to);

        fuse_resolve_and_resume (state, fuse_link_resume);

        return;
}

static int
fuse_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno,
                 fd_t *fd, inode_t *inode, struct iatt *buf,
                 struct iatt *preparent, struct iatt *postparent, dict_t *xdata)
{
        fuse_state_t           *state        = NULL;
        fuse_in_header_t       *finh         = NULL;
        fuse_private_t         *priv         = NULL;
        struct fuse_out_header  fouh         = {0, };
        struct fuse_entry_out   feo          = {0, };
        struct fuse_open_out    foo          = {0, };
        struct iovec            iov_out[3];
        inode_t                *linked_inode = NULL;
        uint64_t                ctx_value    = LOOKUP_NOT_NEEDED;

        state    = frame->root->state;
        priv     = this->private;
        finh     = state->finh;
        foo.open_flags = 0;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret >= 0) {
                foo.fh = (uintptr_t) fd;

                if (((priv->direct_io_mode == 2)
                     && ((state->flags & O_ACCMODE) != O_RDONLY))
                    || (priv->direct_io_mode == 1)
		    || direct_io_mode (xdata))
                        foo.open_flags |= FOPEN_DIRECT_IO;

                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %p (ino=%"PRIu64")",
                        frame->root->unique, gf_fop_list[frame->root->op],
                        state->loc.path, fd, buf->ia_ino);

                buf->ia_blksize = this->ctx->page_size;
                gf_fuse_stat2attr (buf, &feo.attr, priv->enable_ino32);

                linked_inode = inode_link (inode, state->loc.parent,
                                           state->loc.name, buf);

                if (linked_inode != inode) {
                        /*
                           VERY racy code (if used anywhere else)
                           -- don't do this without understanding
                        */
                        inode_unref (fd->inode);
                        fd->inode = inode_ref (linked_inode);
                } else {
                        inode_ctx_set (linked_inode, this, &ctx_value);
                }

                inode_lookup (linked_inode);

                inode_unref (linked_inode);

                feo.nodeid = inode_to_fuse_nodeid (linked_inode);

                feo.entry_valid = calc_timeout_sec (priv->entry_timeout);
                feo.entry_valid_nsec = calc_timeout_nsec (priv->entry_timeout);
                feo.attr_valid = calc_timeout_sec (priv->attribute_timeout);
                feo.attr_valid_nsec =
                  calc_timeout_nsec (priv->attribute_timeout);

                fouh.error = 0;
                iov_out[0].iov_base = &fouh;
                iov_out[1].iov_base = &feo;
#if FUSE_KERNEL_MINOR_VERSION >= 9
                iov_out[1].iov_len = priv->proto_minor >= 9 ?
                                     sizeof (feo) :
                                     FUSE_COMPAT_ENTRY_OUT_SIZE;
#else
                iov_out[1].iov_len = sizeof (feo);
#endif
                iov_out[2].iov_base = &foo;
                iov_out[2].iov_len = sizeof (foo);

                if (send_fuse_iov (this, finh, iov_out, 3) == ENOENT) {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "create(%s) got EINTR", state->loc.path);
                        inode_forget (inode, 1);
                        gf_fd_put (priv->fdtable, state->fd_no);
                        goto out;
                }

                fd_bind (fd);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": %s => -1 (%s)", finh->unique,
                        state->loc.path, strerror (op_errno));
                send_fuse_err (this, finh, op_errno);
                gf_fd_put (priv->fdtable, state->fd_no);
        }
out:
        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

void
fuse_create_resume (fuse_state_t *state)
{
        fd_t           *fd    = NULL;
        fuse_private_t *priv  = NULL;
        fuse_fd_ctx_t  *fdctx = NULL;

        if (!state->loc.parent) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64" CREATE %s/%s resolution failed",
                        state->finh->unique, uuid_utoa (state->resolve.gfid),
                        state->resolve.bname);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        if (state->resolve.op_errno == ENOENT) {
                state->resolve.op_ret = 0;
                state->resolve.op_errno = 0;
        }

        if (state->loc.inode) {
                gf_log (state->this->name, GF_LOG_DEBUG,
                        "inode already present");
                inode_unref (state->loc.inode);
        }

        state->loc.inode = inode_new (state->loc.parent->table);

        fd = fd_create (state->loc.inode, state->finh->pid);
        if (fd == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64" CREATE cannot create a new fd",
                        state->finh->unique);
                send_fuse_err (state->this, state->finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        fdctx = fuse_fd_ctx_check_n_create (state->this, fd);
        if (fdctx == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64" CREATE creation of fdctx failed",
                        state->finh->unique);
                fd_unref (fd);
                send_fuse_err (state->this, state->finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        priv = state->this->private;

        state->fd_no = gf_fd_unused_get (priv->fdtable, fd);

        state->fd = fd_ref (fd);
        fd->flags = state->flags;

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": CREATE %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_create_cbk, GF_FOP_CREATE,
                  create, &state->loc, state->flags, state->mode,
                  state->umask, fd, state->xdata);

}

static void
fuse_create (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
#if FUSE_KERNEL_MINOR_VERSION >= 12
        struct fuse_create_in *fci = msg;
        fuse_private_t        *priv = NULL;
	int32_t                ret = -1;
#else
        struct fuse_open_in *fci = msg;
#endif
        char         *name = (char *)(fci + 1);

        fuse_state_t *state = NULL;

#if FUSE_KERNEL_MINOR_VERSION >= 12
        priv = this->private;
        if (priv->proto_minor < 12)
                name = (char *)((struct fuse_open_in *)msg + 1);
#endif

        GET_STATE (this, finh, state);

        gf_uuid_generate (state->gfid);

        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, name);

        state->mode = fci->mode;
        state->flags = fci->flags;

#if FUSE_KERNEL_MINOR_VERSION >=12
        priv = this->private;
        FUSE_ENTRY_CREATE(this, priv, finh, state, fci, "CREATE");
#endif
        fuse_resolve_and_resume (state, fuse_create_resume);

        return;
}

void
fuse_open_resume (fuse_state_t *state)
{
        fd_t           *fd    = NULL;
        fuse_private_t *priv  = NULL;
        fuse_fd_ctx_t  *fdctx = NULL;

        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "%"PRIu64": OPEN %s resolution failed",
                        state->finh->unique, uuid_utoa (state->resolve.gfid));

                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        fd = fd_create (state->loc.inode, state->finh->pid);
        if (!fd) {
                gf_log ("fuse", GF_LOG_ERROR,
                        "fd is NULL");
                send_fuse_err (state->this, state->finh, ENOENT);
                free_fuse_state (state);
                return;
        }

        fdctx = fuse_fd_ctx_check_n_create (state->this, fd);
        if (fdctx == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": OPEN creation of fdctx failed",
                        state->finh->unique);
                fd_unref (fd);
                send_fuse_err (state->this, state->finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        priv = state->this->private;

        state->fd_no = gf_fd_unused_get (priv->fdtable, fd);
        state->fd = fd_ref (fd);
        fd->flags = state->flags;

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": OPEN %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_fd_cbk, GF_FOP_OPEN,
                  open, &state->loc, state->flags, fd, state->xdata);
}

static int
dokan_open (const char *path, struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "dokan_open => %s", path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_OPEN;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        GET_STATE (this, finh, state);
//        fuse_resolve_continue(state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);
//        fuse_resolve_entry_init (state, &state->resolve, finh->nodeid, path);

        state->flags = fi->flags;

        fuse_resolve_and_resume (state, fuse_open_resume);

        return state->fd_no;
}

static int
fuse_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno,
                struct iovec *vector, int32_t count,
                struct iatt *stbuf, struct iobref *iobref, dict_t *xdata)
{
        fuse_state_t *state = NULL;
        fuse_in_header_t *finh = NULL;
        struct fuse_out_header fouh = {0, };
        struct iovec *iov_out = NULL;

        state = frame->root->state;
        finh = state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret >= 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": READ => %d/%"GF_PRI_SIZET",%"PRId64"/%"PRIu64,
                        frame->root->unique,
                        op_ret, state->size, state->off, stbuf->ia_size);

                iov_out = GF_CALLOC (count + 1, sizeof (*iov_out),
                                     gf_fuse_mt_iovec);
                if (iov_out) {
                        fouh.error = 0;
                        iov_out[0].iov_base = &fouh;

                        memcpy (iov_out + 1, vector, count * sizeof (*iov_out));
                        data_t *data = bin_to_data (iov_out, count * sizeof (*iov_out));
                        if (data != NULL)
                                dict_set (xdata, "buf", data);

                        // GF_FREE (iov_out);

                } else
                        send_fuse_err (this, finh, ENOMEM);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": READ => %d gfid=%s fd=%p (%s)",
                        frame->root->unique, op_ret,
                        (state->fd && state->fd->inode) ?
                        uuid_utoa (state->fd->inode->gfid) : "nil",
                        state->fd, strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

void
fuse_readv_resume (fuse_state_t *state)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": READ (%p, size=%zu, offset=%"PRIu64")",
                state->finh->unique, state->fd, state->size, state->off);

        FUSE_FOP (state, fuse_readv_cbk, GF_FOP_READ, readv, state->fd,
                  state->size, state->off, state->io_flags, state->xdata);
}

static int dokan_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "dokan_read => %s, size=%"GF_PRI_SIZET",offset=%"PRId64,
                path, size, offset);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_OPEN;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fd_t         *fd = NULL;

        GET_STATE (this, finh, state);

        fd = FH_TO_FD (fi->fh);
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        state->lk_owner = fi->lock_owner;
        state->size = size;
        state->off = offset;
        state->io_flags = fi->flags;
        state->xdata = dict_new();

        fuse_resolve_and_resume (state, fuse_readv_resume);



        struct iovec *iov_out = NULL;
        data_t *data = dict_get (state->xdata, "buf");
        iov_out = (struct iovec *) data_to_bin(data);
        if (iov_out == NULL) {

        }

        int len = (iov_out + 1)->iov_len;
        memcpy(buf, (iov_out + 1)->iov_base, len);
        dict_unref(state->xdata);
        GF_FREE(data);

        return len;
}

static int
fuse_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno,
                 struct iatt *stbuf, struct iatt *postbuf, dict_t *xdata)
{
        fuse_state_t *state = NULL;
        fuse_in_header_t *finh = NULL;
        struct fuse_write_out fwo = {0, };

        state = frame->root->state;
        finh = state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret >= 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": WRITE => %d/%"GF_PRI_SIZET",%"PRId64"/%"PRIu64,
                        frame->root->unique,
                        op_ret, state->size, state->off, stbuf->ia_size);

                fwo.size = op_ret;
                send_fuse_obj (this, finh, &fwo);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": WRITE => -1 gfid=%s fd=%p (%s)",
                        frame->root->unique,
                        (state->fd && state->fd->inode) ?
                        uuid_utoa (state->fd->inode->gfid) : "nil", state->fd,
                        strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

void
fuse_write_resume (fuse_state_t *state)
{
        struct iobref *iobref = NULL;
        struct iobuf  *iobuf = NULL;


        iobref = iobref_new ();
        if (!iobref) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "%"PRIu64": WRITE iobref allocation failed",
                        state->finh->unique);
                send_fuse_err (state->this, state->finh, ENOMEM);

                free_fuse_state (state);
                return;
        }

        iobuf = ((fuse_private_t *) (state->this->private))->iobuf;
        iobref_add (iobref, iobuf);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": WRITE (%p, size=%"GF_PRI_SIZET", offset=%"PRId64")",
                state->finh->unique, state->fd, state->size, state->off);

        FUSE_FOP (state, fuse_writev_cbk, GF_FOP_WRITE, writev, state->fd,
                  &state->vector, 1, state->off, state->io_flags, iobref,
                  state->xdata);

        iobref_unref (iobref);
}

// static void
// fuse_write (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_write (const char *path, const char *buf, size_t size,
            off_t offset, struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_write => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_write_in fwi;

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fd_t            *fd = NULL;
#if FUSE_KERNEL_MINOR_VERSION >= 9
        fuse_private_t  *priv = NULL;
        priv = this->private;
#endif

        GET_STATE (this, finh, state);

        fd          = FH_TO_FD (fi->fh);
        state->fd   = fd;
        state->size = size;
        state->off  = offset;

        fwi.fh = fi->fh;
        fwi.offset = offset;
        fwi.size = size;
        fwi.write_flags = FUSE_WRITE_LOCKOWNER;
        fwi.lock_owner = fi->lock_owner;
        fwi.flags = fi->flags;

        /* lets ignore 'fwi->write_flags', but just consider 'fwi->flags' */
#if FUSE_KERNEL_MINOR_VERSION >= 9
        state->io_flags = fi->flags;
#else
	// state->io_flags = fwi->write_flags;
#endif
        /* TODO: may need to handle below flag
           (fwi->write_flags & FUSE_WRITE_CACHE);
        */

        fuse_resolve_fd_init (state, &state->resolve, fd);

        /* See comment by similar code in fuse_settatr */
#if FUSE_KERNEL_MINOR_VERSION >= 9
        priv = this->private;
        if (priv->proto_minor >= 9 && fwi.write_flags & FUSE_WRITE_LOCKOWNER)
                state->lk_owner = fwi.lock_owner;
#endif

        state->vector.iov_base = buf;
        state->vector.iov_len  = size;

        fuse_resolve_and_resume (state, fuse_write_resume);

        return;
}

void
fuse_flush_resume (fuse_state_t *state)
{
        FUSE_FOP (state, fuse_err_cbk, GF_FOP_FLUSH,
                  flush, state->fd, state->xdata);
}

// static void
// fuse_flush (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_flush (const char *path, struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_flush => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_flush_in ffi;

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_FLUSH;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        ffi.fh = fi->fh;
        ffi.lock_owner = fi->lock_owner;

        fd_t         *fd = NULL;

        GET_STATE (this, finh, state);
        fd = FH_TO_FD (ffi.fh);
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        state->lk_owner = ffi.lock_owner;

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": FLUSH %p", finh->unique, fd);

        fuse_resolve_and_resume (state, fuse_flush_resume);

        return 0;
}

int
fuse_internal_release (xlator_t *this, fd_t *fd)
{
        //This is a place holder function to prevent "xlator does not implement
        //release_cbk" Warning log.
        //Actual release happens as part of fuse_release which gets executed
        //when kernel fuse sends it.
        return 0;
}

// static void
// fuse_release (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_release(const char *path, struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_release => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        struct fuse_release_in fri;

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_RELEASE;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fri.fh = fi->fh;
        fri.flags = fi->flags;
        fri.lock_owner = fi->lock_owner;
        fri.release_flags = 0;

        fd_t                   *activefd = NULL;
        fd_t                   *fd        = NULL;
        uint64_t                val       = 0;
        int                     ret       = 0;
        fuse_fd_ctx_t          *fdctx     = NULL;
        fuse_private_t         *priv      = NULL;

        GET_STATE (this, finh, state);
        fd = FH_TO_FD (fri.fh);
        state->fd = fd;

        priv = this->private;

        fuse_log_eh (this, "RELEASE(): %"PRIu64":, fd: %p, gfid: %s",
                     finh->unique, fd, uuid_utoa (fd->inode->gfid));

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": RELEASE %p", finh->unique, state->fd);

        ret = fd_ctx_del (fd, this, &val);
        if (!ret) {
                fdctx = (fuse_fd_ctx_t *)(unsigned long)val;
                if (fdctx) {
                        activefd = fdctx->activefd;
                        if (activefd) {
                                fd_unref (activefd);
                        }

                        GF_FREE (fdctx);
                }
        }
        fd_unref (fd);

        state->fd = NULL;

        gf_fdptr_put (priv->fdtable, fd);

        send_fuse_err (this, finh, 0);

        free_fuse_state (state);
        return;
}


void
fuse_fsync_resume (fuse_state_t *state)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": FSYNC %p", state->finh->unique,
                state->fd);

        /* fsync_flags: 1 means "datasync" (no defines for this) */
        FUSE_FOP (state, fuse_fsync_cbk, GF_FOP_FSYNC,
                  fsync, state->fd, (state->flags & 1), state->xdata);
}

// static void
// fuse_fsync (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_fsync(const char *path, int isdatasync,
        struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_fsync => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fd_t            *fd = NULL;
#if FUSE_KERNEL_MINOR_VERSION >= 9
        fuse_private_t  *priv = NULL;
        priv = this->private;
#endif

        GET_STATE (this, finh, state);
        fd = FH_TO_FD (fi->fh);
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        state->flags = isdatasync ? 1 : 0;
        fuse_resolve_and_resume (state, fuse_fsync_resume);
        return;
}

void
fuse_opendir_resume (fuse_state_t *state)
{
        fd_t           *fd    = NULL;
        fuse_private_t *priv  = NULL;
        fuse_fd_ctx_t  *fdctx = NULL;

        priv = state->this->private;

        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": OPENDIR (%s) resolution failed",
                        state->finh->unique, uuid_utoa (state->resolve.gfid));
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        fd = fd_create (state->loc.inode, state->finh->pid);
        if (fd == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": OPENDIR fd creation failed",
                        state->finh->unique);
                send_fuse_err (state->this, state->finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        fdctx = fuse_fd_ctx_check_n_create (state->this, fd);
        if (fdctx == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": OPENDIR creation of fdctx failed",
                        state->finh->unique);
                fd_unref (fd);
                send_fuse_err (state->this, state->finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        state->fd = fd_ref (fd);
        state->fd_no = gf_fd_unused_get (priv->fdtable, fd);

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": OPENDIR %s", state->finh->unique,
                state->loc.path);

        FUSE_FOP (state, fuse_fd_cbk, GF_FOP_OPENDIR,
                  opendir, &state->loc, fd, state->xdata);
}

static void
fuse_opendir (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        /*
        struct fuse_open_in *foi = msg;
         */

        fuse_state_t *state = NULL;

        GET_STATE (this, finh, state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        fuse_resolve_and_resume (state, fuse_opendir_resume);
}

unsigned char
d_type_from_stat (struct iatt *buf)
{
        unsigned char d_type;

        if (IA_ISLNK (buf->ia_type)) {
                d_type = DT_LNK;

        } else if (IA_ISDIR (buf->ia_type)) {
                d_type = DT_DIR;

        } else if (IA_ISFIFO (buf->ia_type)) {
                d_type = DT_FIFO;

        } else if (IA_ISSOCK (buf->ia_type)) {
                d_type = DT_SOCK;

        } else if (IA_ISCHR (buf->ia_type)) {
                d_type = DT_CHR;

        } else if (IA_ISBLK (buf->ia_type)) {
                d_type = DT_BLK;

        } else if (IA_ISREG (buf->ia_type)) {
                d_type = DT_REG;

        } else {
                d_type = DT_UNKNOWN;
        }

        return d_type;
}

static int
fuse_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, gf_dirent_t *entries,
                  dict_t *xdata)
{
        fuse_state_t *state = NULL;
        fuse_in_header_t *finh = NULL;
        size_t        size = 0;
        size_t        max_size = 0;
        char         *buf = NULL;
        gf_dirent_t  *entry = NULL;
        struct fuse_dirent *fde = NULL;
        fuse_private_t *priv = NULL;

        state = frame->root->state;
        finh  = state->finh;
        priv = state->this->private;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret < 0) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": READDIR => -1 (%s)", frame->root->unique,
                        strerror (op_errno));

                send_fuse_err (this, finh, op_errno);
                goto out;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": READDIR => %d/%"GF_PRI_SIZET",%"PRId64,
                frame->root->unique, op_ret, state->size, state->off);

        list_for_each_entry (entry, &entries->list, list) {
                size_t fde_size = FUSE_DIRENT_ALIGN (FUSE_NAME_OFFSET +
                                                     strlen (entry->d_name));
                max_size += fde_size;

                if (max_size > state->size) {
                        /* we received too many entries to fit in the reply */
                        max_size -= fde_size;
                        break;
                }
        }

        if (max_size == 0) {
                send_fuse_data (this, finh, 0, 0);
                goto out;
        }

        buf = GF_CALLOC (1, max_size, gf_fuse_mt_char);
        if (!buf) {
                gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                        "%"PRIu64": READDIR => -1 (%s)", frame->root->unique,
                        strerror (ENOMEM));
                send_fuse_err (this, finh, ENOMEM);
                goto out;
        }

        size = 0;
        list_for_each_entry (entry, &entries->list, list) {
                fde = (struct fuse_dirent *)(buf + size);
                gf_fuse_fill_dirent (entry, fde, priv->enable_ino32);
                size += FUSE_DIRENT_SIZE (fde);

                if (size == max_size)
                        break;
        }

        send_fuse_data (this, finh, buf, size);

        /* TODO: */
        /* gf_link_inodes_from_dirent (this, state->fd->inode, entries); */

out:
        free_fuse_state (state);
        STACK_DESTROY (frame->root);
        GF_FREE (buf);
        return 0;

}

void
fuse_readdir_resume (fuse_state_t *state)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": READDIR (%p, size=%"GF_PRI_SIZET", offset=%"PRId64")",
                state->finh->unique, state->fd, state->size, state->off);

        FUSE_FOP (state, fuse_readdir_cbk, GF_FOP_READDIR,
                  readdir, state->fd, state->size, state->off, state->xdata);
}

// static void
// fuse_readdir (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
       off_t offset, struct fuse_file_info *fi)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_readdir => %s", path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();
        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_READDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        strncpy(finh + sizeof(sizeof (*finh)), path, 128);

        fd_t         *fd = NULL;

        GET_STATE (this, finh, state);
        // state->size = fri->size;
        // state->off = fri->offset;
        fd = FH_TO_FD (fi->fh);
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        fuse_resolve_and_resume (state, fuse_readdir_resume);
}

#if FUSE_KERNEL_MINOR_VERSION >= 20
static int
fuse_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		   int32_t op_ret, int32_t op_errno, gf_dirent_t *entries,
		   dict_t *xdata)
{
	fuse_state_t *state = NULL;
	fuse_in_header_t *finh = NULL;
        size_t        max_size = 0;
        size_t        size = 0;
	char         *buf = NULL;
	gf_dirent_t  *entry = NULL;
	struct fuse_direntplus *fde = NULL;
	struct fuse_entry_out *feo = NULL;
	fuse_private_t         *priv   = NULL;

	state = frame->root->state;
	finh  = state->finh;
	priv = this->private;

	if (op_ret < 0) {
		gf_log ("glusterfs-fuse", GF_LOG_WARNING,
			"%"PRIu64": READDIRP => -1 (%s)", frame->root->unique,
			strerror (op_errno));

		send_fuse_err (this, finh, op_errno);
		goto out;
	}

	gf_log ("glusterfs-fuse", GF_LOG_TRACE,
		"%"PRIu64": READDIRP => %d/%"GF_PRI_SIZET",%"PRId64,
		frame->root->unique, op_ret, state->size, state->off);

	list_for_each_entry (entry, &entries->list, list) {
                size_t fdes = FUSE_DIRENT_ALIGN (FUSE_NAME_OFFSET_DIRENTPLUS +
                                                 strlen (entry->d_name));
                max_size += fdes;

                if (max_size > state->size) {
                        /* we received too many entries to fit in the reply */
                        max_size -= fdes;
                        break;
                }
	}

	if (max_size == 0) {
		send_fuse_data (this, finh, 0, 0);
		goto out;
	}

	buf = GF_CALLOC (1, max_size, gf_fuse_mt_char);
	if (!buf) {
		gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
			"%"PRIu64": READDIRP => -1 (%s)", frame->root->unique,
			strerror (ENOMEM));
		send_fuse_err (this, finh, ENOMEM);
		goto out;
	}

	size = 0;
	list_for_each_entry (entry, &entries->list, list) {
		inode_t *linked_inode;

		fde = (struct fuse_direntplus *)(buf + size);
		feo = &fde->entry_out;

		if (priv->enable_ino32)
			fde->dirent.ino = GF_FUSE_SQUASH_INO(entry->d_ino);
		else
			fde->dirent.ino = entry->d_ino;

		fde->dirent.off = entry->d_off;
		fde->dirent.type = entry->d_type;
		fde->dirent.namelen = strlen (entry->d_name);
		strncpy (fde->dirent.name, entry->d_name, fde->dirent.namelen);
		size += FUSE_DIRENTPLUS_SIZE (fde);

		if (!entry->inode)
			goto next_entry;

		entry->d_stat.ia_blksize = this->ctx->page_size;
		gf_fuse_stat2attr (&entry->d_stat, &feo->attr, priv->enable_ino32);

		linked_inode = inode_link (entry->inode, state->fd->inode,
					   entry->d_name, &entry->d_stat);
		if (!linked_inode)
			goto next_entry;

                if ((strcmp(entry->d_name, ".") != 0) &&
                    (strcmp(entry->d_name, "..") != 0)) {
                        inode_lookup (linked_inode);
                        inode_set_need_lookup (linked_inode, this);
                }

		feo->nodeid = inode_to_fuse_nodeid (linked_inode);

		inode_unref (linked_inode);

		feo->entry_valid =
			calc_timeout_sec (priv->entry_timeout);
		feo->entry_valid_nsec =
			calc_timeout_nsec (priv->entry_timeout);
		feo->attr_valid =
			calc_timeout_sec (priv->attribute_timeout);
		feo->attr_valid_nsec =
			calc_timeout_nsec (priv->attribute_timeout);

next_entry:
                if (size == max_size)
                        break;
	}

	send_fuse_data (this, finh, buf, size);
out:
	free_fuse_state (state);
	STACK_DESTROY (frame->root);
	GF_FREE (buf);
	return 0;

}

void
fuse_readdirp_resume (fuse_state_t *state)
{
	gf_log ("glusterfs-fuse", GF_LOG_TRACE,
		"%"PRIu64": READDIRP (%p, size=%"GF_PRI_SIZET", offset=%"PRId64")",
		state->finh->unique, state->fd, state->size, state->off);

	FUSE_FOP (state, fuse_readdirp_cbk, GF_FOP_READDIRP,
		  readdirp, state->fd, state->size, state->off, state->xdata);
}


static void
fuse_readdirp (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
	struct fuse_read_in *fri = msg;

	fuse_state_t *state = NULL;
	fd_t         *fd = NULL;

	GET_STATE (this, finh, state);
	state->size = fri->size;
	state->off = fri->offset;
	fd = FH_TO_FD (fri->fh);
	state->fd = fd;

	fuse_resolve_fd_init (state, &state->resolve, fd);

	fuse_resolve_and_resume (state, fuse_readdirp_resume);
}
#endif

#if FUSE_KERNEL_MINOR_VERSION >= 19
#ifdef FALLOC_FL_KEEP_SIZE
static int
fuse_fallocate_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
		   struct iatt *postbuf, dict_t *xdata)
{
	return fuse_err_cbk(frame, cookie, this, op_ret, op_errno, xdata);
}

static void
fuse_fallocate_resume(fuse_state_t *state)
{
	gf_log("glusterfs-fuse", GF_LOG_TRACE,
	       "%"PRIu64": FALLOCATE (%p, flags=%d, size=%zu, offset=%"PRId64")",
	       state->finh->unique, state->fd, state->flags, state->size,
	       state->off);

	if (state->flags & FALLOC_FL_PUNCH_HOLE)
		FUSE_FOP(state, fuse_fallocate_cbk, GF_FOP_DISCARD, discard,
			 state->fd, state->off, state->size, state->xdata);
	else
		FUSE_FOP(state, fuse_fallocate_cbk, GF_FOP_FALLOCATE, fallocate,
			 state->fd, (state->flags & FALLOC_FL_KEEP_SIZE),
			 state->off, state->size, state->xdata);
}

static void
fuse_fallocate(xlator_t *this, fuse_in_header_t *finh, void *msg)
{
	struct fuse_fallocate_in *ffi = msg;
	fuse_state_t *state = NULL;

	GET_STATE(this, finh, state);
	state->off = ffi->offset;
	state->size = ffi->length;
	state->flags = ffi->mode;
	state->fd = FH_TO_FD(ffi->fh);

	fuse_resolve_fd_init(state, &state->resolve, state->fd);
	fuse_resolve_and_resume(state, fuse_fallocate_resume);
}
#endif /* FALLOC_FL_KEEP_SIZE */
#endif /* FUSE minor version >= 19 */

static void
fuse_releasedir (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        struct fuse_release_in *fri       = msg;
        fd_t                   *activefd = NULL;
        uint64_t                val       = 0;
        int                     ret       = 0;
        fuse_state_t           *state     = NULL;
        fuse_fd_ctx_t          *fdctx     = NULL;
        fuse_private_t         *priv      = NULL;

        GET_STATE (this, finh, state);
        state->fd = FH_TO_FD (fri->fh);

        priv = this->private;

        fuse_log_eh (this, "RELEASEDIR (): %"PRIu64": fd: %p, gfid: %s",
                     finh->unique, state->fd,
                     uuid_utoa (state->fd->inode->gfid));

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": RELEASEDIR %p", finh->unique, state->fd);

        ret = fd_ctx_del (state->fd, this, &val);

        if (!ret) {
                fdctx = (fuse_fd_ctx_t *)(unsigned long)val;
                if (fdctx) {
                        activefd = fdctx->activefd;
                        if (activefd) {
                                fd_unref (activefd);
                        }

                        GF_FREE (fdctx);
                }
        }

        fd_unref (state->fd);

        gf_fdptr_put (priv->fdtable, state->fd);

        state->fd = NULL;

        send_fuse_err (this, finh, 0);

        free_fuse_state (state);

        return;
}

void
fuse_fsyncdir_resume (fuse_state_t *state)
{
        FUSE_FOP (state, fuse_err_cbk, GF_FOP_FSYNCDIR,
                  fsyncdir, state->fd, (state->flags & 1), state->xdata);

}

static void
fuse_fsyncdir (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        struct fuse_fsync_in *fsi = msg;

        fuse_state_t *state = NULL;
        fd_t         *fd = NULL;

        fd = FH_TO_FD (fsi->fh);

        GET_STATE (this, finh, state);
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        state->flags = fsi->fsync_flags;
        fuse_resolve_and_resume (state, fuse_fsyncdir_resume);

        return;
}

static int
fuse_statfs_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, struct statvfs *buf,
                 dict_t *xdata)
{
        fuse_state_t *state = NULL;
        fuse_in_header_t *finh = NULL;
        fuse_private_t   *priv = NULL;
        struct fuse_statfs_out fso = {{0, }, };

        state = frame->root->state;
        priv  = this->private;
        finh  = state->finh;

        fuse_log_eh (this, "op_ret: %d, op_errno: %d, %"PRIu64": %s()",
                     op_ret, op_errno, frame->root->unique,
                     gf_fop_list[frame->root->op]);

        if (op_ret == 0) {
#ifndef GF_DARWIN_HOST_OS
                /* MacFUSE doesn't respect anyof these tweaks */
                buf->f_blocks *= buf->f_frsize;
                buf->f_blocks /= this->ctx->page_size;

                buf->f_bavail *= buf->f_frsize;
                buf->f_bavail /= this->ctx->page_size;

                buf->f_bfree *= buf->f_frsize;
                buf->f_bfree /= this->ctx->page_size;

                buf->f_frsize = buf->f_bsize =this->ctx->page_size;
#endif /* GF_DARWIN_HOST_OS */
                fso.st.bsize   = buf->f_bsize;
                fso.st.frsize  = buf->f_frsize;
                fso.st.blocks  = buf->f_blocks;
                fso.st.bfree   = buf->f_bfree;
                fso.st.bavail  = buf->f_bavail;
                fso.st.files   = buf->f_files;
                fso.st.ffree   = buf->f_ffree;
                fso.st.namelen = buf->f_namemax;

                priv->proto_minor >= 4 ?
                send_fuse_obj (this, finh, &fso) :
                send_fuse_data (this, finh, &fso, FUSE_COMPAT_STATFS_SIZE);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": ERR => -1 (%s)", frame->root->unique,
                        strerror (op_errno));
                send_fuse_err (this, finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}

void
fuse_statfs_resume (fuse_state_t *state)
{
        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": STATFS (%s) resolution fail",
                        state->finh->unique, uuid_utoa (state->resolve.gfid));

                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": STATFS", state->finh->unique);

        FUSE_FOP (state, fuse_statfs_cbk, GF_FOP_STATFS,
                  statfs, &state->loc, state->xdata);
}


// static void
// fuse_statfs (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_statfs (const char *path, struct statvfs *stbuf)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_statfs => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        GET_STATE (this, finh, state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        fuse_resolve_and_resume (state, fuse_statfs_resume);
}

void
fuse_setxattr_resume (fuse_state_t *state)
{
        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": SETXATTR %s/%"PRIu64" (%s) "
                        "resolution failed",
                        state->finh->unique, uuid_utoa (state->resolve.gfid),
                        state->finh->nodeid, state->name);
                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

#ifdef GF_TEST_FFOP
        state->fd = fd_lookup (state->loc.inode, state->finh->pid);
#endif /* GF_TEST_FFOP */

        if (state->fd) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": SETXATTR %p/%"PRIu64" (%s)", state->finh->unique,
                        state->fd, state->finh->nodeid, state->name);

                FUSE_FOP (state, fuse_setxattr_cbk, GF_FOP_FSETXATTR,
                          fsetxattr, state->fd, state->xattr, state->flags,
                          state->xdata);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": SETXATTR %s/%"PRIu64" (%s)", state->finh->unique,
                        state->loc.path, state->finh->nodeid, state->name);

                FUSE_FOP (state, fuse_setxattr_cbk, GF_FOP_SETXATTR,
                          setxattr, &state->loc, state->xattr, state->flags,
                          state->xdata);
        }
}


// static void
// fuse_setxattr (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_setxattr(const char *path, const char *name, const char *value,
        size_t size, int flags)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_setxattr => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_SETXATTR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        GET_STATE (this, finh, state);

        struct fuse_private *priv = NULL;

        char         *dict_value = NULL;
        int32_t       ret = -1;
        char *newkey = NULL;

        priv = this->private;

        GET_STATE (this, finh, state);

#ifdef GF_DARWIN_HOST_OS
        if (fsi->position) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": SETXATTR %s/%"PRIu64" (%s):"
                        "refusing positioned setxattr",
                        finh->unique, state->loc.path, finh->nodeid, name);
                send_fuse_err (this, finh, EINVAL);
                FREE (finh);
                return;
        }
#endif

        if (fuse_ignore_xattr_set (priv, name)) {
                (void) send_fuse_err (this, finh, 0);
                return;
        }

        if (!priv->acl) {
                if ((strcmp (name, POSIX_ACL_ACCESS_XATTR) == 0) ||
                    (strcmp (name, POSIX_ACL_DEFAULT_XATTR) == 0)) {
                        send_fuse_err (this, finh, EOPNOTSUPP);
                        GF_FREE (finh);
                        return;
                }
        }

        ret = fuse_check_selinux_cap_xattr (priv, name);
        if (ret) {
                send_fuse_err (this, finh, EOPNOTSUPP);
                GF_FREE (finh);
                return;
        }

        /* Check if the command is for changing the log
           level of process or specific xlator */
        ret = is_gf_log_command (this, name, value);
        if (ret >= 0) {
                send_fuse_err (this, finh, ret);
                GF_FREE (finh);
                return;
        }

        if (!strcmp ("inode-invalidate", name)) {
                gf_log ("fuse", GF_LOG_TRACE,
                        "got request to invalidate %"PRIu64, finh->nodeid);
                send_fuse_err (this, finh, 0);
#if FUSE_KERNEL_MINOR_VERSION >= 11
                fuse_invalidate_entry (this, finh->nodeid);
#endif
                GF_FREE (finh);
                return;
        }

        if (!strcmp (GFID_XATTR_KEY, name) || !strcmp (GF_XATTR_VOL_ID_KEY, name)) {
                send_fuse_err (this, finh, EPERM);
                GF_FREE (finh);
                return;
        }

        state->size = size;

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        state->xattr = get_new_dict ();
        if (!state->xattr) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "%"PRIu64": SETXATTR dict allocation failed",
                        finh->unique);

                send_fuse_err (this, finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        ret = fuse_flip_xattr_ns (priv, name, &newkey);
        if (ret) {
                send_fuse_err (this, finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        if (size > 0) {
                /*
                 * Many translators expect setxattr values to be strings, but
                 * neither dict_get_str nor data_to_str do any checking or
                 * fixups to make sure that's the case.  To avoid nasty
                 * surprises, allocate an extra byte and add a NUL here.
                 */
                dict_value = memdup (value, size+1);
                dict_value[size] = '\0';
        }
        dict_set (state->xattr, newkey,
                  data_from_dynptr ((void *)dict_value, size));
        dict_ref (state->xattr);

        state->flags = flags;
        state->name = newkey;

        fuse_resolve_and_resume (state, fuse_setxattr_resume);

        return;
}


static void
send_fuse_xattr (xlator_t *this, fuse_in_header_t *finh, const char *value,
                 size_t size, size_t expected)
{
        struct fuse_getxattr_out fgxo;

        /* linux kernel limits the size of xattr value to 64k */
        if (size > GLUSTERFS_XATTR_LEN_MAX)
                send_fuse_err (this, finh, E2BIG);
        else if (expected) {
                /* if callback for getxattr and asks for value */
                if (size > expected)
                        /* reply would be bigger than
                         * what was asked by kernel */
                        send_fuse_err (this, finh, ERANGE);
                else
                        send_fuse_data (this, finh, (void *)value, size);
        } else {
                fgxo.size = size;
                send_fuse_obj (this, finh, &fgxo);
        }
}

/* filter out xattrs that need not be visible on the
 * mount point. this is _specifically_ for geo-rep
 * as of now, to prevent Rsync from crying out loud
 * when it tries to setxattr() for selinux xattrs
 */
static int
fuse_filter_xattr(char *key)
{
        int need_filter = 0;
        struct fuse_private *priv = get_fuse_xlator()->private;

        if ((priv->client_pid == GF_CLIENT_PID_GSYNCD)
            && fnmatch ("*.selinux*", key, FNM_PERIOD) == 0)
                need_filter = 1;

        return need_filter;
}


static int
fuse_xattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, dict_t *dict, dict_t *xdata)
{
        char           *value = "";
        fuse_state_t   *state = NULL;
        fuse_in_header_t *finh = NULL;
        data_t         *value_data = NULL;
        int             ret = -1;
        int32_t         len = 0;
        int32_t         len_next = 0;

        state = frame->root->state;
        finh  = state->finh;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret >= 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": %s() %s => %d", frame->root->unique,
                        gf_fop_list[frame->root->op], state->loc.path, op_ret);

                /* if successful */
                if (state->name) {
                        /* if callback for getxattr */
                        value_data = dict_get (dict, state->name);
                        if (value_data) {

                                ret = value_data->len; /* Don't return the value for '\0' */
                                value = value_data->data;

                                send_fuse_xattr (this, finh, value, ret, state->size);
                                /* if(ret >...)...else if...else */
                        } else {
                                send_fuse_err (this, finh, ENODATA);
                        } /* if(value_data)...else */
                } else {
                        /* if callback for listxattr */
                        /* we need to invoke fuse_filter_xattr() twice. Once
                         * while counting size and then while filling buffer
                         */
                        len = dict_keys_join (NULL, 0, dict, fuse_filter_xattr);
                        if (len < 0)
                                goto out;

                        value = alloca (len + 1);
                        if (!value)
                                goto out;

                        len_next = dict_keys_join (value, len, dict,
                                                   fuse_filter_xattr);
                        if (len_next != len)
                                gf_log (get_fuse_xlator()->name, GF_LOG_ERROR,
                                        "sizes not equal %d != %d",
                                        len, len_next);

                        send_fuse_xattr (this, finh, value, len, state->size);
                } /* if(state->name)...else */
        } else {
                /* if failure - no need to check if listxattr or getxattr */
                if (op_errno != ENODATA && op_errno != ENOATTR) {
                        if (op_errno == ENOTSUP) {
                                GF_LOG_OCCASIONALLY (gf_fuse_xattr_enotsup_log,
                                                     "glusterfs-fuse",
                                                     GF_LOG_ERROR,
                                                     "extended attribute not "
                                                     "supported by the backend "
                                                     "storage");
                        } else {
                                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                        "%"PRIu64": %s(%s) %s => -1 (%s)",
                                        frame->root->unique,
                                        gf_fop_list[frame->root->op], state->name,
                                        state->loc.path, strerror (op_errno));
                        }
                } else {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "%"PRIu64": %s(%s) %s => -1 (%s)",
                                frame->root->unique,
                                gf_fop_list[frame->root->op], state->name,
                                state->loc.path, strerror (op_errno));
                } /* if(op_errno!= ENODATA)...else */

                send_fuse_err (this, finh, op_errno);
        } /* if(op_ret>=0)...else */

out:
        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}


void
fuse_getxattr_resume (fuse_state_t *state)
{
        char *value  = NULL;

        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": GETXATTR %s/%"PRIu64" (%s) "
                        "resolution failed",
                        state->finh->unique,
                        uuid_utoa (state->resolve.gfid),
                        state->finh->nodeid, state->name);

                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

#ifdef GF_TEST_FFOP
        state->fd = fd_lookup (state->loc.inode, state->finh->pid);
#endif /* GF_TEST_FFOP */

        if (state->name &&
            (strcmp (state->name, VIRTUAL_GFID_XATTR_KEY) == 0)) {
                /* send glusterfs gfid in binary form */

                value = GF_CALLOC (16 + 1, sizeof(char),
                                   gf_common_mt_char);
                if (!value) {
                        send_fuse_err (state->this, state->finh, ENOMEM);
                        goto internal_out;
                }
                memcpy (value, state->loc.inode->gfid, 16);

                send_fuse_xattr (get_fuse_xlator(), state->finh, value, 16, state->size);
                GF_FREE (value);
        internal_out:
                free_fuse_state (state);
                return;
        }

        if (state->name &&
            (strcmp (state->name, VIRTUAL_GFID_XATTR_KEY_STR) == 0)) {
                /* transform binary gfid to canonical form */

                value = GF_CALLOC (UUID_CANONICAL_FORM_LEN + 1, sizeof(char),
                                   gf_common_mt_char);
                if (!value) {
                        send_fuse_err (state->this, state->finh, ENOMEM);
                        goto internal_out1;
                }
                uuid_utoa_r (state->loc.inode->gfid, value);

                send_fuse_xattr (get_fuse_xlator(), state->finh, value,
                                 UUID_CANONICAL_FORM_LEN, state->size);
                GF_FREE (value);
        internal_out1:
                free_fuse_state (state);
                return;
        }


        if (state->fd) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": GETXATTR %p/%"PRIu64" (%s)", state->finh->unique,
                        state->fd, state->finh->nodeid, state->name);

                FUSE_FOP (state, fuse_xattr_cbk, GF_FOP_FGETXATTR,
                          fgetxattr, state->fd, state->name, state->xdata);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": GETXATTR %s/%"PRIu64" (%s)", state->finh->unique,
                        state->loc.path, state->finh->nodeid, state->name);

                FUSE_FOP (state, fuse_xattr_cbk, GF_FOP_GETXATTR,
                          getxattr, &state->loc, state->name, state->xdata);
        }
}


// static void
// fuse_getxattr (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_getxattr (const char *path, const char *name, char *value,
                        size_t size)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_getxattr => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_SETXATTR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        GET_STATE (this, finh, state);

        struct fuse_private *priv = NULL;

        char         *dict_value = NULL;
        int32_t       ret = -1;

        priv = this->private;

        GET_STATE (this, finh, state);

        int                      rv       = 0;
        int                     op_errno  = EINVAL;
        char                    *newkey   = NULL;

        ret = 0;
        priv = this->private;
        GET_STATE (this, finh, state);

#ifdef GF_DARWIN_HOST_OS
        if (fgxi->position) {
                /* position can be used only for
                 * resource fork queries which we
                 * don't support anyway... so handling
                 * it separately is just sort of a
                 * matter of aesthetics, not strictly
                 * necessary.
                 */

                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": GETXATTR %s/%"PRIu64" (%s):"
                        "refusing positioned getxattr",
                        finh->unique, state->loc.path, finh->nodeid, name);
                op_errno = EINVAL;
                goto err;
        }
#endif

        if (!priv->acl) {
                if ((strcmp (name, POSIX_ACL_ACCESS_XATTR) == 0) ||
                    (strcmp (name, POSIX_ACL_DEFAULT_XATTR) == 0)) {
                        op_errno = ENOTSUP;
                        goto err;
                }
        }

        ret = fuse_check_selinux_cap_xattr (priv, name);
        if (ret) {
                op_errno = ENODATA;
                goto err;
        }

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        rv = fuse_flip_xattr_ns (priv, name, &newkey);
        if (rv) {
                op_errno = ENOMEM;
                goto err;
        }

        state->size = size;
        state->name = newkey;

        fuse_resolve_and_resume (state, fuse_getxattr_resume);

        return;
 err:
        send_fuse_err (this, finh, op_errno);
        free_fuse_state (state);
        return;
}


void
fuse_listxattr_resume (fuse_state_t *state)
{
        if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "%"PRIu64": LISTXATTR %s/%"PRIu64
                        "resolution failed", state->finh->unique,
                        uuid_utoa (state->resolve.gfid), state->finh->nodeid);

                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

#ifdef GF_TEST_FFOP
        state->fd = fd_lookup (state->loc.inode, state->finh->pid);
#endif /* GF_TEST_FFOP */

        if (state->fd) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": LISTXATTR %p/%"PRIu64, state->finh->unique,
                        state->fd, state->finh->nodeid);

                FUSE_FOP (state, fuse_xattr_cbk, GF_FOP_FGETXATTR,
                          fgetxattr, state->fd, NULL, state->xdata);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": LISTXATTR %s/%"PRIu64, state->finh->unique,
                        state->loc.path, state->finh->nodeid);

                FUSE_FOP (state, fuse_xattr_cbk, GF_FOP_GETXATTR,
                          getxattr, &state->loc, NULL, state->xdata);
        }
}


// static void
// fuse_listxattr (xlator_t *this, fuse_in_header_t *finh, void *msg)
static int
fuse_listxattr (const char *path, char *list, size_t size)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_listxattr => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        GET_STATE (this, finh, state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        state->size = size;

        fuse_resolve_and_resume (state, fuse_listxattr_resume);

        return;
}

void
fuse_removexattr_resume (fuse_state_t *state)
{
         if (!state->loc.inode) {
                gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                        "%"PRIu64": REMOVEXATTR %s/%"PRIu64" (%s) "
                        "resolution failed",
                        state->finh->unique, uuid_utoa (state->resolve.gfid),
                        state->finh->nodeid, state->name);

                send_fuse_err (state->this, state->finh,
                               state->resolve.op_errno);
                free_fuse_state (state);
                return;
        }

#ifdef GF_TEST_FFOP
        state->fd = fd_lookup (state->loc.inode, state->finh->pid);
#endif /* GF_TEST_FFOP */

        if (state->fd) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": REMOVEXATTR %p/%"PRIu64" (%s)", state->finh->unique,
                        state->fd, state->finh->nodeid, state->name);

                FUSE_FOP (state, fuse_removexattr_cbk, GF_FOP_FREMOVEXATTR,
                          fremovexattr, state->fd, state->name, state->xdata);
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": REMOVEXATTR %s/%"PRIu64" (%s)", state->finh->unique,
                        state->loc.path, state->finh->nodeid, state->name);

                FUSE_FOP (state, fuse_removexattr_cbk, GF_FOP_REMOVEXATTR,
                          removexattr, &state->loc, state->name, state->xdata);
        }
}


// static void
// fuse_removexattr (xlator_t *this, fuse_in_header_t *finh, void *msg)

static int
fuse_removexattr (const char *path, const char *name)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_removexattr => %s",
                path);
        __asm__("int $3");

        xlator_t *this = get_fuse_xlator();

        fuse_in_header_t *finh = NULL;
        fuse_state_t *state = NULL;
        struct fuse_context *ctx = get_fuse_header_in();

        const size_t msg0_size = sizeof (*finh) + 128;
        finh = GF_CALLOC (1, msg0_size, gf_fuse_mt_iov_base);

        finh->len = msg0_size;
        finh->opcode = FUSE_MKDIR;
        finh->unique = 0;
        finh->nodeid = 1;
        finh->uid = ctx->uid;
        finh->gid = ctx->gid;
        finh->pid = ctx->pid;

        GET_STATE (this, finh, state);

        fuse_private_t *priv = NULL;
        int32_t       ret = -1;
        char *newkey = NULL;

        if (!strcmp (GFID_XATTR_KEY, name) || !strcmp (GF_XATTR_VOL_ID_KEY, name)) {
                send_fuse_err (this, finh, EPERM);
                GF_FREE (finh);
                return;
        }

        priv = this->private;

        GET_STATE (this, finh, state);

        fuse_resolve_inode_init (state, &state->resolve, finh->nodeid);

        ret = fuse_flip_xattr_ns (priv, name, &newkey);
        if (ret) {
                send_fuse_err (this, finh, ENOMEM);
                free_fuse_state (state);
                return;
        }

        state->name = newkey;

        fuse_resolve_and_resume (state, fuse_removexattr_resume);
        return;
}


static int gf_fuse_lk_enosys_log;

static int
fuse_getlk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct gf_flock *lock,
                dict_t *xdata)
{
        fuse_state_t *state = NULL;

        state = frame->root->state;
        struct fuse_lk_out flo = {{0, }, };

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": ERR => 0", frame->root->unique);
                flo.lk.type = lock->l_type;
                flo.lk.pid  = lock->l_pid;
                if (lock->l_type == F_UNLCK)
                        flo.lk.start = flo.lk.end = 0;
                else {
                        flo.lk.start = lock->l_start;
                        flo.lk.end = lock->l_len ?
                                     (lock->l_start + lock->l_len - 1) :
                                     OFFSET_MAX;
                }
                send_fuse_obj (this, state->finh, &flo);
        } else {
                if (op_errno == ENOSYS) {
                        gf_fuse_lk_enosys_log++;
                        if (!(gf_fuse_lk_enosys_log % GF_UNIVERSAL_ANSWER)) {
                                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                        "GETLK not supported. loading "
                                        "'features/posix-locks' on server side "
                                        "will add GETLK support.");
                        }
                } else {
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "%"PRIu64": ERR => -1 (%s)",
                                frame->root->unique, strerror (op_errno));
                }
                send_fuse_err (this, state->finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}


void
fuse_getlk_resume (fuse_state_t *state)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": GETLK %p", state->finh->unique, state->fd);

        FUSE_FOP (state, fuse_getlk_cbk, GF_FOP_LK,
                  lk, state->fd, F_GETLK, &state->lk_lock, state->xdata);
}


static void
fuse_getlk (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        struct fuse_lk_in *fli = msg;

        fuse_state_t *state = NULL;
        fd_t         *fd = NULL;

        fd = FH_TO_FD (fli->fh);
        GET_STATE (this, finh, state);
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        convert_fuse_file_lock (&fli->lk, &state->lk_lock,
                                fli->owner);

        state->lk_owner = fli->owner;

        fuse_resolve_and_resume (state, fuse_getlk_resume);

        return;
}


static int
fuse_setlk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct gf_flock *lock,
                dict_t *xdata)
{
        uint32_t      op    = 0;
        fuse_state_t *state = NULL;

        state = frame->root->state;
        op    = state->finh->opcode;

        fuse_log_eh_fop(this, state, frame, op_ret, op_errno);

        if (op_ret == 0) {
                gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                        "%"PRIu64": ERR => 0", frame->root->unique);
                fd_lk_insert_and_merge (state->fd,
                                        (op == FUSE_SETLK) ? F_SETLK : F_SETLKW,
                                        &state->lk_lock);

                send_fuse_err (this, state->finh, 0);
        } else {
                if (op_errno == ENOSYS) {
                        gf_fuse_lk_enosys_log++;
                        if (!(gf_fuse_lk_enosys_log % GF_UNIVERSAL_ANSWER)) {
                                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                        "SETLK not supported. loading "
                                        "'features/posix-locks' on server side "
                                        "will add SETLK support.");
                        }
                } else if (op_errno == EAGAIN) {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "Returning EAGAIN Flock: "
                                "start=%llu, len=%llu, pid=%llu, lk-owner=%s",
                                (unsigned long long) state->lk_lock.l_start,
                                (unsigned long long) state->lk_lock.l_len,
                                (unsigned long long) state->lk_lock.l_pid,
                                lkowner_utoa (&frame->root->lk_owner));
                } else  {
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "%"PRIu64": ERR => -1 (%s)",
                                frame->root->unique, strerror (op_errno));
                }

                send_fuse_err (this, state->finh, op_errno);
        }

        free_fuse_state (state);
        STACK_DESTROY (frame->root);

        return 0;
}


void
fuse_setlk_resume (fuse_state_t *state)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "%"PRIu64": SETLK%s %p", state->finh->unique,
                state->finh->opcode == FUSE_SETLK ? "" : "W", state->fd);

        FUSE_FOP (state, fuse_setlk_cbk, GF_FOP_LK, lk, state->fd,
                  state->finh->opcode == FUSE_SETLK ? F_SETLK : F_SETLKW,
                  &state->lk_lock, state->xdata);
}


static void
fuse_setlk (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        struct fuse_lk_in *fli = msg;

        fuse_state_t *state = NULL;
        fd_t         *fd = NULL;

        fd = FH_TO_FD (fli->fh);
        GET_STATE (this, finh, state);
        state->finh = finh;
        state->fd = fd;

        fuse_resolve_fd_init (state, &state->resolve, fd);

        convert_fuse_file_lock (&fli->lk, &state->lk_lock,
                                fli->owner);

        state->lk_owner = fli->owner;

        fuse_resolve_and_resume (state, fuse_setlk_resume);

        return;
}

//static void
//fuse_init (xlator_t *this, fuse_in_header_t *finh, void *msg)
static void *
fuse_init (struct fuse_conn_info *conn)
{
        xlator_t             *this      = get_fuse_xlator();
        fuse_private_t       *priv      = NULL;
        int                   ret       = 0;

        gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                "llllllllllllllllllllllllllllllll=%"PRIu64", dddd%"PRIu64"pid=%d",
                this, this->private, getpid());

        priv = this->private;

        if (priv->init_recvd) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "got INIT after first message");

                return NULL;
        }

        priv->init_recvd = 1;
        priv->proto_minor = conn->proto_minor;

        /* Used for 'reverse invalidation of inode' */
#ifdef NEVER
                ret = gf_thread_create (&messenger, NULL, notify_kernel_loop,
					this);
                if (ret != 0) {
                        gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                "failed to start messenger daemon (%s)",
                                strerror(errno));

                        close (priv->fd);
                        goto out;
                }
                priv->reverse_fuse_thread_started = _gf_true;
#endif /* NEVER */

        /* TODO: fix cache */
        priv->fopen_keep_cache = 0;

        gf_log ("glusterfs-fuse", GF_LOG_INFO,
                "FUSE inited with protocol versions:"
                " glusterfs %d.%d dokan %d.%d",
                FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION,
                conn->proto_major, conn->proto_minor);
        return NULL;
}


static void
fuse_enosys (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
        send_fuse_err (this, finh, ENOSYS);

        GF_FREE (finh);
}



struct fuse_first_lookup {
        pthread_mutex_t  mutex;
        pthread_cond_t   cond;
        char             fin;
};

int
fuse_first_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                       int32_t op_ret, int32_t op_errno,
                       inode_t *inode, struct iatt *buf, dict_t *xattr,
                       struct iatt *postparent)
{
        struct fuse_first_lookup *stub = NULL;

        stub = frame->local;

        if (op_ret == 0) {
                gf_log (this->name, GF_LOG_TRACE,
                        "first lookup on root succeeded.");
        } else {
                gf_log (this->name, GF_LOG_DEBUG,
                        "first lookup on root failed.");
        }

        pthread_mutex_lock (&stub->mutex);
        {
                stub->fin = 1;
                pthread_cond_broadcast (&stub->cond);
        }
        pthread_mutex_unlock (&stub->mutex);

        return 0;
}

/*
void fuse_lookup_inode_by_path(const char *path, struct fuse_file_info *fi, fuse_in_header *finh)
{
        loc_t                      loc = {0, };

        if (strcmp(path, "/") == 0) {
                inode = 1;
        }

        loc.path = path;
        loc.name = "";
        loc.inode = fuse_ino_to_inode (fi->nodeid, this);
        gf_uuid_copy (loc.gfid, loc.inode->gfid);
        loc.parent = NULL;

        fi->fh;
}
*/

int
fuse_first_lookup (xlator_t *this)
{
        fuse_private_t            *priv = NULL;
        loc_t                      loc = {0, };
        call_frame_t              *frame = NULL;
        xlator_t                  *xl = NULL;
        dict_t                    *dict = NULL;
        struct fuse_first_lookup   stub;
        uuid_t                     gfid;
        int                        ret = -1;

        priv = this->private;

        loc.path = "/";
        loc.name = "";
        loc.inode = fuse_ino_to_inode (1, this);
        gf_uuid_copy (loc.gfid, loc.inode->gfid);
        loc.parent = NULL;

        dict = dict_new ();
        frame = create_frame (this, this->ctx->pool);
        if (!frame) {
                gf_log ("fuse", GF_LOG_ERROR, "failed to create frame");
                goto out;
        }

        frame->root->type = GF_OP_TYPE_FOP;

        xl = priv->active_subvol;

        pthread_mutex_init (&stub.mutex, NULL);
        pthread_cond_init (&stub.cond, NULL);
        stub.fin = 0;

        frame->local = &stub;

        memset (gfid, 0, 16);
        gfid[15] = 1;
        ret = dict_set_static_bin (dict, "gfid-req", gfid, 16);
        if (ret) {
                gf_log (xl->name, GF_LOG_ERROR, "failed to set 'gfid-req'");
        } else {
                STACK_WIND (frame, fuse_first_lookup_cbk, xl, xl->fops->lookup,
                            &loc, dict);

                pthread_mutex_lock (&stub.mutex);
                {
                        while (!stub.fin) {
                                pthread_cond_wait (&stub.cond, &stub.mutex);
                        }
                }
                pthread_mutex_unlock (&stub.mutex);
        }

        dict_unref (dict);

        pthread_mutex_destroy (&stub.mutex);
        pthread_cond_destroy (&stub.cond);

        frame->local = NULL;
        STACK_DESTROY (frame->root);

out:
        inode_unref(loc.inode);

        return ret;
}


int
fuse_nameless_lookup (xlator_t *this, xlator_t *xl, uuid_t gfid, loc_t *loc)
{
        int          ret          = -1;
        dict_t      *xattr_req    = NULL;
        struct iatt  iatt         = {0, };
        inode_t     *linked_inode = NULL;
        uint64_t     ctx_value    = LOOKUP_NOT_NEEDED;

        if ((loc == NULL) || (xl == NULL)) {
                ret = -EINVAL;
                goto out;
        }

        if (loc->inode == NULL) {
                loc->inode = inode_new (xl->itable);
                if (loc->inode == NULL) {
                        ret = -ENOMEM;
                        goto out;
                }
        }

        gf_uuid_copy (loc->gfid, gfid);

        xattr_req = dict_new ();
        if (xattr_req == NULL) {
                ret = -ENOMEM;
                goto out;
        }

        ret = syncop_lookup (xl, loc, &iatt, NULL, xattr_req, NULL);
        if (ret < 0)
                goto out;

        linked_inode = inode_link (loc->inode, NULL, NULL, &iatt);
        if (linked_inode == loc->inode)
                inode_ctx_set (linked_inode, this, &ctx_value);

        inode_unref (loc->inode);
        loc->inode = linked_inode;

        ret = 0;
out:
        if (xattr_req != NULL) {
                dict_unref (xattr_req);
        }

        return ret;
}


int
fuse_migrate_fd_open (xlator_t *this, fd_t *basefd, fd_t *oldfd,
                      xlator_t *old_subvol, xlator_t *new_subvol)
{
        loc_t          loc       = {0, };
        fd_t          *newfd     = NULL, *old_activefd = NULL;
        fuse_fd_ctx_t *basefd_ctx = NULL;
        fuse_fd_ctx_t *newfd_ctx = NULL;
        int            ret       = 0, flags = 0;

        ret = inode_path (basefd->inode, NULL, (char **)&loc.path);
        if (ret < 0) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "cannot construct path of gfid (%s) failed"
                        "(old-subvolume:%s-%d new-subvolume:%s-%d)",
                        uuid_utoa (basefd->inode->gfid),
                        old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id);
                goto out;
        }

        gf_uuid_copy (loc.gfid, basefd->inode->gfid);

        loc.inode = inode_find (new_subvol->itable, basefd->inode->gfid);

        if (loc.inode == NULL) {
                ret = fuse_nameless_lookup (this, new_subvol,
                                            basefd->inode->gfid, &loc);
                if (ret < 0) {
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "name-less lookup of gfid (%s) failed (%s)"
                                "(old-subvolume:%s-%d new-subvolume:%s-%d)",
                                uuid_utoa (basefd->inode->gfid),
                                strerror (-ret),
                                old_subvol->name, old_subvol->graph->id,
                                new_subvol->name, new_subvol->graph->id);
                        ret = -1;
                        goto out;
                }

        }

        basefd_ctx = fuse_fd_ctx_get (this, basefd);
        GF_VALIDATE_OR_GOTO ("glusterfs-fuse", basefd_ctx, out);

        newfd = fd_create (loc.inode, basefd->pid);
        if (newfd == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "cannot create new fd, hence not migrating basefd "
                        "(ptr:%p inode-gfid:%s) "
                        "(old-subvolume:%s-%d new-subvolume:%s-%d)", basefd,
                        uuid_utoa (loc.inode->gfid),
                        old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id);
                ret = -1;
                goto out;
        }

        newfd->flags = basefd->flags;
	if (newfd->lk_ctx)
		fd_lk_ctx_unref (newfd->lk_ctx);

        newfd->lk_ctx = fd_lk_ctx_ref (oldfd->lk_ctx);

        newfd_ctx = fuse_fd_ctx_check_n_create (this, newfd);
        GF_VALIDATE_OR_GOTO ("glusterfs-fuse", newfd_ctx, out);

        if (IA_ISDIR (basefd->inode->ia_type)) {
                ret = syncop_opendir (new_subvol, &loc, newfd, NULL, NULL);
        } else {
                flags = basefd->flags & ~(O_CREAT | O_EXCL | O_TRUNC);
                ret = syncop_open (new_subvol, &loc, flags, newfd, NULL, NULL);
        }

        if (ret < 0) {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "open on basefd (ptr:%p inode-gfid:%s) failed (%s)"
                        "(old-subvolume:%s-%d new-subvolume:%s-%d)", basefd,
                        uuid_utoa (basefd->inode->gfid), strerror (-ret),
                        old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id);
                ret = -1;
                goto out;
        }

        fd_bind (newfd);

        LOCK (&basefd->lock);
        {
                if (basefd_ctx->activefd != NULL) {
                        old_activefd = basefd_ctx->activefd;
                }

                basefd_ctx->activefd = newfd;
        }
        UNLOCK (&basefd->lock);

        if (old_activefd != NULL) {
                fd_unref (old_activefd);
        }

        gf_log ("glusterfs-fuse", GF_LOG_INFO,
                "migrated basefd (%p) to newfd (%p) (inode-gfid:%s)"
                "(old-subvolume:%s-%d new-subvolume:%s-%d)", basefd, newfd,
                uuid_utoa (basefd->inode->gfid),
		old_subvol->name, old_subvol->graph->id,
                new_subvol->name, new_subvol->graph->id);

        ret = 0;

out:
        loc_wipe (&loc);

        return ret;
}

int
fuse_migrate_locks (xlator_t *this, fd_t *basefd, fd_t *oldfd,
                    xlator_t *old_subvol, xlator_t *new_subvol)
{
        int	 ret      = -1;
        dict_t	*lockinfo = NULL;
        void    *ptr      = NULL;
	fd_t    *newfd    = NULL;
        fuse_fd_ctx_t *basefd_ctx         = NULL;


	if (!oldfd->lk_ctx || fd_lk_ctx_empty (oldfd->lk_ctx))
		return 0;

        basefd_ctx = fuse_fd_ctx_get (this, basefd);
        GF_VALIDATE_OR_GOTO ("glusterfs-fuse", basefd_ctx, out);

        LOCK (&basefd->lock);
        {
                newfd = fd_ref (basefd_ctx->activefd);
        }
        UNLOCK (&basefd->lock);

        ret = syncop_fgetxattr (old_subvol, oldfd, &lockinfo,
                                GF_XATTR_LOCKINFO_KEY, NULL, NULL);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
			"getting lockinfo failed while migrating locks"
			"(oldfd:%p newfd:%p inode-gfid:%s)"
			"(old-subvol:%s-%d new-subvol:%s-%d)",
			oldfd, newfd, uuid_utoa (newfd->inode->gfid),
			old_subvol->name, old_subvol->graph->id,
			new_subvol->name, new_subvol->graph->id);
                ret = -1;
                goto out;
        }

        ret = dict_get_ptr (lockinfo, GF_XATTR_LOCKINFO_KEY, &ptr);
        if (ptr == NULL) {
                ret = 0;
                gf_log (this->name, GF_LOG_INFO,
                        "No lockinfo present on any of the bricks "
			"(oldfd: %p newfd:%p inode-gfid:%s) "
                        "(old-subvol:%s-%d new-subvol:%s-%d)",
			oldfd, newfd, uuid_utoa (newfd->inode->gfid),
			old_subvol->name, old_subvol->graph->id,
			new_subvol->name, new_subvol->graph->id);

                goto out;
        }

        ret = syncop_fsetxattr (new_subvol, newfd, lockinfo, 0, NULL, NULL);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
			"migrating locks failed (oldfd:%p newfd:%p "
			"inode-gfid:%s) (old-subvol:%s-%d new-subvol:%s-%d)",
			oldfd, newfd, uuid_utoa (newfd->inode->gfid),
			old_subvol->name, old_subvol->graph->id,
			new_subvol->name, new_subvol->graph->id);
                ret = -1;
                goto out;
        }

out:
	if (newfd)
		fd_unref (newfd);

        if (lockinfo != NULL) {
                dict_unref (lockinfo);
        }

        return ret;
}


int
fuse_migrate_fd (xlator_t *this, fd_t *basefd, xlator_t *old_subvol,
                 xlator_t *new_subvol)
{
        int            ret                = -1;
        char           create_in_progress = 0;
        fuse_fd_ctx_t *basefd_ctx         = NULL;
        fd_t          *oldfd              = NULL;

        basefd_ctx = fuse_fd_ctx_get (this, basefd);
        GF_VALIDATE_OR_GOTO ("glusterfs-fuse", basefd_ctx, out);

        LOCK (&basefd->lock);
        {
                oldfd = basefd_ctx->activefd ? basefd_ctx->activefd
                        : basefd;
                fd_ref (oldfd);
        }
        UNLOCK (&basefd->lock);

        LOCK (&oldfd->inode->lock);
        {
                if (gf_uuid_is_null (oldfd->inode->gfid)) {
                        create_in_progress = 1;
                } else {
                        create_in_progress = 0;
                }
        }
        UNLOCK (&oldfd->inode->lock);

        if (create_in_progress) {
                gf_log ("glusterfs-fuse", GF_LOG_INFO,
                        "create call on fd (%p) is in progress "
                        "(basefd-ptr:%p basefd-inode.gfid:%s), "
                        "hence deferring migration till application does an "
                        "fd based operation on this fd"
                        "(old-subvolume:%s-%d, new-subvolume:%s-%d)",
                        oldfd, basefd, uuid_utoa (basefd->inode->gfid),
                        old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id);

                ret = 0;
                goto out;
        }

        if (oldfd->inode->table->xl == old_subvol) {
                if (IA_ISDIR (oldfd->inode->ia_type))
                        ret = syncop_fsyncdir (old_subvol, oldfd, 0, NULL,
                                               NULL);
                else
                        ret = syncop_fsync (old_subvol, oldfd, 0, NULL, NULL);

                if (ret < 0) {
                        gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                                "syncop_fsync(dir) failed (%s) on fd (%p)"
                                "(basefd:%p basefd-inode.gfid:%s) "
                                "(old-subvolume:%s-%d new-subvolume:%s-%d)",
                                strerror (-ret), oldfd, basefd,
                                uuid_utoa (basefd->inode->gfid),
                                old_subvol->name, old_subvol->graph->id,
                                new_subvol->name, new_subvol->graph->id);
                }
        } else {
                gf_log ("glusterfs-fuse", GF_LOG_WARNING,
                        "basefd (ptr:%p inode-gfid:%s) was not "
                        "migrated during previous graph switch"
                        "(old-subvolume:%s-%d new-subvolume: %s-%d)", basefd,
                        basefd->inode->gfid,
                        old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id);
        }

        ret = fuse_migrate_fd_open (this, basefd, oldfd, old_subvol,
                                    new_subvol);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING, "open corresponding to "
                        "basefd (ptr:%p inode-gfid:%s) in new graph failed "
                        "(old-subvolume:%s-%d new-subvolume:%s-%d)", basefd,
                        uuid_utoa (basefd->inode->gfid), old_subvol->name,
                        old_subvol->graph->id, new_subvol->name,
                        new_subvol->graph->id);
                goto out;
        }

        ret = fuse_migrate_locks (this, basefd, oldfd, old_subvol,
                                  new_subvol);
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "migrating locks from old-subvolume (%s-%d) to "
                        "new-subvolume (%s-%d) failed (inode-gfid:%s oldfd:%p "
                        "basefd:%p)", old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id,
                        uuid_utoa (basefd->inode->gfid), oldfd, basefd);

        }
out:
        if (ret < 0) {
                gf_log (this->name, GF_LOG_WARNING, "migration of basefd "
                        "(ptr:%p inode-gfid:%s) failed"
                        "(old-subvolume:%s-%d new-subvolume:%s-%d)", basefd,
                        oldfd ? uuid_utoa (oldfd->inode->gfid) : NULL,
                        old_subvol->name, old_subvol->graph->id,
                        new_subvol->name, new_subvol->graph->id);
        }

        fd_unref (oldfd);

        return ret;
}


int
fuse_handle_opened_fds (xlator_t *this, xlator_t *old_subvol,
                        xlator_t *new_subvol)
{
        fuse_private_t *priv      = NULL;
        fdentry_t      *fdentries = NULL;
        uint32_t        count     = 0;
        fdtable_t      *fdtable   = NULL;
        int             i         = 0;
        fd_t           *fd        = NULL;
        int32_t         ret       = 0;
        fuse_fd_ctx_t  *fdctx     = NULL;

        priv = this->private;

        fdtable = priv->fdtable;

        fdentries = gf_fd_fdtable_copy_all_fds (fdtable, &count);
        if (fdentries != NULL) {
                for (i = 0; i < count; i++) {
                        fd = fdentries[i].fd;
                        if (fd == NULL)
                                continue;

                        ret = fuse_migrate_fd (this, fd, old_subvol,
                                               new_subvol);

                        fdctx = fuse_fd_ctx_get (this, fd);
                        if (fdctx) {
                                LOCK (&fd->lock);
                                {
                                        if (ret < 0) {
                                                fdctx->migration_failed = 1;
                                        } else {
                                                fdctx->migration_failed = 0;
                                        }
                                }
                                UNLOCK (&fd->lock);
                        }
                }

                for (i = 0; i < count ; i++) {
                        fd = fdentries[i].fd;
                        if (fd)
                                fd_unref (fd);
                }

                GF_FREE (fdentries);
        }

        return 0;
}


static int
fuse_handle_blocked_locks (xlator_t *this, xlator_t *old_subvol,
                           xlator_t *new_subvol)
{
        return 0;
}


static int
fuse_graph_switch_task (void *data)
{
        fuse_graph_switch_args_t *args = NULL;

        args = data;
        if (args == NULL) {
                goto out;
        }

        /* don't change the order of handling open fds and blocked locks, since
         * the act of opening files also reacquires granted locks in new graph.
         */
        fuse_handle_opened_fds (args->this, args->old_subvol, args->new_subvol);

        fuse_handle_blocked_locks (args->this, args->old_subvol,
                                   args->new_subvol);

out:
        return 0;
}


fuse_graph_switch_args_t *
fuse_graph_switch_args_alloc (void)
{
        fuse_graph_switch_args_t *args = NULL;

        args = GF_CALLOC (1, sizeof (*args), gf_fuse_mt_graph_switch_args_t);
        if (args == NULL) {
                goto out;
        }

out:
        return args;
}


void
fuse_graph_switch_args_destroy (fuse_graph_switch_args_t *args)
{
        if (args == NULL) {
                goto out;
        }

        GF_FREE (args);
out:
        return;
}


int
fuse_handle_graph_switch (xlator_t *this, xlator_t *old_subvol,
                          xlator_t *new_subvol)
{
        call_frame_t             *frame = NULL;
        int32_t                   ret   = -1;
        fuse_graph_switch_args_t *args  = NULL;

        frame = create_frame (this, this->ctx->pool);
        if (frame == NULL) {
                goto out;
        }

        args = fuse_graph_switch_args_alloc ();
        if (args == NULL) {
                goto out;
        }

        args->this = this;
        args->old_subvol = old_subvol;
        args->new_subvol = new_subvol;

        ret = synctask_new (this->ctx->env, fuse_graph_switch_task, NULL, frame,
                            args);
        if (ret == -1) {
                gf_log (this->name, GF_LOG_WARNING, "starting sync-task to "
                        "handle graph switch failed");
                goto out;
        }

        ret = 0;
out:
        if (args != NULL) {
                fuse_graph_switch_args_destroy (args);
        }

        if (frame != NULL) {
                STACK_DESTROY (frame->root);
        }

        return ret;
}


int
fuse_graph_sync (xlator_t *this)
{
        fuse_private_t *priv                = NULL;
        int             need_first_lookup   = 0;
        int             ret                 = 0;
        xlator_t       *old_subvol          = NULL, *new_subvol = NULL;
        uint64_t        winds_on_old_subvol = 0;

        priv = this->private;

        pthread_mutex_lock (&priv->sync_mutex);
        {
                if (!priv->next_graph)
                        goto unlock;

                old_subvol = priv->active_subvol;
                new_subvol = priv->active_subvol = priv->next_graph->top;
                priv->next_graph = NULL;
                need_first_lookup = 1;

                while (!priv->event_recvd) {
                        ret = pthread_cond_wait (&priv->sync_cond,
                                                 &priv->sync_mutex);
                        if (ret != 0) {
                                  gf_log (this->name, GF_LOG_DEBUG,
                                          "timedwait returned non zero value "
                                          "ret: %d errno: %d", ret, errno);
                                  break;
                        }
                }
        }
unlock:
        pthread_mutex_unlock (&priv->sync_mutex);

        if (need_first_lookup) {
                fuse_first_lookup (this);
        }

        if ((old_subvol != NULL) && (new_subvol != NULL)) {
                fuse_handle_graph_switch (this, old_subvol, new_subvol);

                pthread_mutex_lock (&priv->sync_mutex);
                {
                        old_subvol->switched = 1;
                        winds_on_old_subvol = old_subvol->winds;
                }
                pthread_mutex_unlock (&priv->sync_mutex);

                if (winds_on_old_subvol == 0) {
                        xlator_notify (old_subvol, GF_EVENT_PARENT_DOWN,
                                       old_subvol, NULL);
                }
        }

        return 0;
}

int
fuse_get_mount_status (xlator_t *this)
{
        int             kid_status = -1;
        fuse_private_t *priv = this->private;

        if (read(priv->status_pipe[0],&kid_status, sizeof(kid_status)) < 0) {
                gf_log (this->name, GF_LOG_ERROR, "could not get mount status");
                kid_status = -1;
        }
        gf_log (this->name, GF_LOG_DEBUG, "mount status is %d", kid_status);

        close(priv->status_pipe[0]);
        close(priv->status_pipe[1]);
        return kid_status;
}


static void *
fuse_thread_proc (void *data)
{
        char                     *mount_point = NULL;
        xlator_t                 *this = NULL;
        fuse_private_t           *priv = NULL;
        ssize_t                   res = 0;
        struct iobuf             *iobuf = NULL;
        fuse_in_header_t         *finh = NULL;
        struct iovec              iov_in[2];
        void                     *msg = NULL;
        const size_t              msg0_size = sizeof (*finh) + 128;
        fuse_handler_t          **fuse_ops = NULL;
        struct pollfd             pfd[2] = {{0,}};
        struct mount_data        *mnt_data = NULL;
        gf_boolean_t              mount_data_allocated = _gf_false;
        int                       ret = -1;

        this = data;
        priv = this->private;
        fuse_ops = priv->fuse_ops;

        THIS = this;

        iov_in[0].iov_len = sizeof (*finh) + sizeof (struct fuse_write_in);
        iov_in[1].iov_len = ((struct iobuf_pool *)this->ctx->iobuf_pool)
                              ->default_page_size;
        priv->msg0_len_p = &iov_in[0].iov_len;

        {
                /* THIS has to be reset here */
                THIS = this;
                gf_log (this->name, GF_LOG_TRACE,
                        "ssssssssssssssssssssssssssssssssssssssssspriv%"PRIu64, this->private);
        }

        mnt_data = (struct mount_data *) MALLOC (sizeof(struct mount_data));
        if (!mnt_data) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "Out of memory");
                goto cleanup_exit;
        }
        mount_data_allocated = _gf_true;
        mnt_data->private = priv;
        mnt_data->mountpoint = priv->mount_point;
        mnt_data->fsname = "glusterfs"; // TODO: fix this name
        mnt_data->mountflags = 0;
        mnt_data->mnt_param = 0;
        mnt_data->status_fd = priv->status_pipe[1];

        ret = gf_thread_create (&priv->fuse_thread, NULL,
        			mount_proc, mnt_data);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "pthread_create() failed (%s)",
                        strerror (errno));
                goto cleanup_exit;
        }

        return NULL;

cleanup_exit:
        if (mount_data_allocated) {
                GF_FREE (mnt_data);
        }

        return NULL;
}

int32_t
fuse_itable_dump (xlator_t  *this)
{
        fuse_private_t *priv = NULL;

        if (!this)
                 return -1;

        priv = this->private;

        if (priv && priv->active_subvol) {
                gf_proc_dump_add_section("xlator.mount.fuse.itable");
                inode_table_dump(priv->active_subvol->itable,
                                 "xlator.mount.fuse.itable");
        }
        return 0;
}

int32_t
fuse_priv_dump (xlator_t  *this)
{
        fuse_private_t  *private = NULL;

        if (!this)
                return -1;

        private = this->private;

        if (!private)
                return -1;

        gf_proc_dump_add_section("xlator.mount.fuse.priv");

        gf_proc_dump_write("proto_minor", "%u",
                            private->proto_minor);
        gf_proc_dump_write("volfile", "%s",
                            private->volfile?private->volfile:"None");
        gf_proc_dump_write("volfile_size", "%d",
                            private->volfile_size);
        gf_proc_dump_write("mount_point", "%s",
                            private->mount_point);
        gf_proc_dump_write("iobuf", "%u",
                            private->iobuf);
        gf_proc_dump_write("fuse_thread_started", "%d",
                            (int)private->fuse_thread_started);
        gf_proc_dump_write("direct_io_mode", "%d",
                            private->direct_io_mode);
        gf_proc_dump_write("entry_timeout", "%lf",
                            private->entry_timeout);
        gf_proc_dump_write("attribute_timeout", "%lf",
                            private->attribute_timeout);
        gf_proc_dump_write("init_recvd", "%d",
                            (int)private->init_recvd);
        gf_proc_dump_write("strict_volfile_check", "%d",
                            (int)private->strict_volfile_check);
        gf_proc_dump_write("reverse_thread_started", "%d",
                           (int)private->reverse_fuse_thread_started);
        gf_proc_dump_write("use_readdirp", "%d", private->use_readdirp);

        return 0;
}

int
fuse_history_dump (xlator_t *this)
{
        int      ret    = -1;
        char key_prefix[GF_DUMP_MAX_BUF_LEN] = {0,};

        GF_VALIDATE_OR_GOTO ("fuse", this, out);
        GF_VALIDATE_OR_GOTO (this->name, this->history, out);

        gf_proc_dump_build_key (key_prefix, "xlator.mount.fuse",
                                "history");
        gf_proc_dump_add_section (key_prefix);
        eh_dump (this->history, NULL, dump_history_fuse);

        ret = 0;
out:
        return ret;
}

int
dump_history_fuse (circular_buffer_t *cb, void *data)
{
        char       timestr[256] = {0,};

        gf_time_fmt (timestr, sizeof timestr, cb->tv.tv_sec, gf_timefmt_F_HMS);

        snprintf (timestr + strlen (timestr), 256 - strlen (timestr),
                  ".%"GF_PRI_SUSECONDS, cb->tv.tv_usec);
        gf_proc_dump_write ("TIME", "%s", timestr);

        gf_proc_dump_write ("message", "%s\n", cb->data);

        return 0;
}

int
fuse_graph_setup (xlator_t *this, glusterfs_graph_t *graph)
{
        inode_table_t     *itable     = NULL;
        int                ret        = 0, winds = 0;
        fuse_private_t    *priv       = NULL;
        glusterfs_graph_t *prev_graph = NULL;

        priv = this->private;

        pthread_mutex_lock (&priv->sync_mutex);
        {
                /* handle the case of more than one CHILD_UP on same graph */
                if ((priv->active_subvol == graph->top) || graph->used) {
                        goto unlock;
                }

                itable = inode_table_new (0, graph->top);
                if (!itable) {
                        ret = -1;
                        goto unlock;
                }

                ((xlator_t *)graph->top)->itable = itable;

                prev_graph = priv->next_graph;

                if ((prev_graph != NULL) && (prev_graph->id > graph->id)) {
                        /* there was a race and an old graph was initialised
                         * before new one.
                         */
                        prev_graph = graph;
                } else {
                        priv->next_graph = graph;
                        priv->event_recvd = 0;
                }

                if (prev_graph != NULL)
                        winds = ((xlator_t *)prev_graph->top)->winds;

		/* set post initializing next_graph i to preserve
                 * critical section update and bails on error */
                graph->used = 1;
        }
        pthread_mutex_unlock (&priv->sync_mutex);

        if ((prev_graph != NULL) && (winds == 0)) {
                xlator_notify (prev_graph->top, GF_EVENT_PARENT_DOWN,
                               prev_graph->top, NULL);
        }

        gf_log ("fuse", GF_LOG_INFO, "switched to graph %d",
                ((graph) ? graph->id : 0));

        return ret;
unlock:
        pthread_mutex_unlock (&priv->sync_mutex);

        return ret;
}


int
notify (xlator_t *this, int32_t event, void *data, ...)
{
        int32_t             ret     = 0;
        fuse_private_t     *private = NULL;
        gf_boolean_t        start_thread = _gf_false;
        glusterfs_graph_t  *graph = NULL;

        private = this->private;

        graph = data;

        gf_log ("fuse", GF_LOG_TRACE, "ccccccccccccccccccccccccccccccccccccthis=%"PRIu64, this);

        gf_log ("fuse", GF_LOG_DEBUG, "got event %d on graph %d",
                event, ((graph) ? graph->id : 0));

        switch (event)
        {
        case GF_EVENT_GRAPH_NEW:
                break;

        case GF_EVENT_CHILD_UP:
        case GF_EVENT_CHILD_DOWN:
        case GF_EVENT_CHILD_CONNECTING:
        {
                if (graph) {
                        ret = fuse_graph_setup (this, graph);
                        if (ret)
                                gf_log (this->name, GF_LOG_WARNING,
                                        "failed to setup the graph");
                }

                if ((event == GF_EVENT_CHILD_UP)
                    || (event == GF_EVENT_CHILD_DOWN)) {
                        pthread_mutex_lock (&private->sync_mutex);
                        {
                                private->event_recvd = 1;
                                pthread_cond_broadcast (&private->sync_cond);
                        }
                        pthread_mutex_unlock (&private->sync_mutex);
                }

                pthread_mutex_lock (&private->sync_mutex);
                {
                        if (!private->fuse_thread_started) {
                                private->fuse_thread_started = 1;
                                start_thread = _gf_true;
                        }
                }
                pthread_mutex_unlock (&private->sync_mutex);

                if (start_thread) {
                        ret = gf_thread_create (&private->fuse_thread, NULL,
						fuse_thread_proc, this);
                        if (ret != 0) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "pthread_create() failed (%s)",
                                        strerror (errno));
                                break;
                        }
                }

                break;
        }

        case GF_EVENT_AUTH_FAILED:
        {
                /* Authentication failure is an error and glusterfs should stop */
               gf_log (this->name, GF_LOG_ERROR, "Server authenication failed. Shutting down.");
               fini (this);
               break;
        }

        default:
                break;
        }

        return ret;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_fuse_mt_end + 1);

        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR, "Memory accounting init"
                                "failed");
                return ret;
        }

        return ret;
}

static int
fuse_chmod (const char *path, mode_t mode)
{       __asm__("int $3");
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_chmod => %s",
                path);


	return 0;
}

static int
fuse_chown (const char *path, uid_t uid, gid_t gid)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_chown => %s",
                path);

        __asm__("int $3");
	return 0;
}

static int
fuse_truncate (const char *path, off_t size)
{
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "fuse_truncate => %s",
                path);
        __asm__("int $3");
	return 0;
}

struct fuse_operations dokan_operations = {
	.getattr	= fuse_getattr,
	.readlink	= fuse_readlink,
        .mknod          = fuse_mknod,
        .mkdir          = fuse_mkdir,
        .unlink         = fuse_unlink,
        .rmdir          = fuse_rmdir,
        .symlink        = fuse_symlink,
        .rename         = fuse_rename,
        .link           = fuse_link,
        .chmod          = fuse_chmod,
        .chown          = fuse_chown,
        .truncate       = fuse_truncate,
        .utime          = NULL,
        .open           = dokan_open,
        .read           = dokan_read,
        .write          = fuse_write,
        .statfs         = fuse_statfs,
        .flush          = fuse_flush,
        .release        = fuse_release,
        .fsync          = fuse_fsync,
        .setxattr       = fuse_setxattr,
        .getxattr       = fuse_getxattr,
        .listxattr      = fuse_listxattr,
        .removexattr    = fuse_removexattr,
        .opendir        = NULL,
        .readdir	= fuse_readdir,
        .releasedir     = NULL,
        .fsyncdir       = NULL,
        .init           = fuse_init,
        .destroy        = NULL,
	.access		= fuse_access,
        .create         = NULL,
        .ftruncate      = NULL,
        .fgetattr       = NULL,
        .lock           = NULL,
        .utimens        = NULL,
        .bmap           = NULL,

#ifdef _WIN32
	/* these to support extented windows calls */
	.win_get_attributes = NULL,
	.win_set_attributes = NULL,
	.win_set_times      = NULL,
#endif
};


static fuse_handler_t *fuse_std_ops[FUSE_OP_HIGH] = {

};


static fuse_handler_t *fuse_dump_ops[FUSE_OP_HIGH];


static void
fuse_dumper (xlator_t *this, fuse_in_header_t *finh, void *msg)
{
#ifdef NEVER
        fuse_private_t *priv = NULL;
        struct iovec diov[3];
        char r = 'R';
        int ret = 0;

        priv = this->private;

        diov[0].iov_base = &r;
        diov[0].iov_len  = 1;
        diov[1].iov_base = finh;
        diov[1].iov_len  = sizeof (*finh);
        diov[2].iov_base = msg;
        diov[2].iov_len  = finh->len - sizeof (*finh);

        pthread_mutex_lock (&priv->fuse_dump_mutex);
        ret = writev (priv->fuse_dump_fd, diov, 3);
        pthread_mutex_unlock (&priv->fuse_dump_mutex);
        if (ret == -1)
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "failed to dump fuse message (R): %s",
                        strerror (errno));

        priv->fuse_ops0[finh->opcode] (this, finh, msg);
#endif /* NEVER */
}

static void *
mount_proc(void *data)
{
        struct mount_data *md = (struct mount_data *)data;
        int ret = -1;
        gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrthis=%"PRIu64, data);

        ret = gf_fuse_mount(md->mountpoint, md->fsname, md->mountflags,
                md->mountflags, md->status_fd);
        if (ret != 0) {
                gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                        "mount failed (%s)", md->mountpoint);
        }
        gf_log ("glusterfs-fuse", GF_LOG_TRACE,
                "mount process exited.");

        FREE (data);
        return NULL;
}

int
init (xlator_t *this_xl)
{
        int                ret = 0;
        dict_t            *options = NULL;
        char              *value_string = NULL;
        cmd_args_t        *cmd_args = NULL;
        char              *fsname = NULL;
        fuse_private_t    *priv = NULL;
        struct stat        stbuf = {0,};
        int                i = 0;
        int                xl_name_allocated = 0;
        int                fsname_allocated = 0;
        glusterfs_ctx_t   *ctx = NULL;
        gf_boolean_t       sync_to_mount = _gf_false;
        gf_boolean_t       fopen_keep_cache = _gf_false;
        unsigned long      mntflags = 0;
        char              *mnt_args = NULL;
        eh_t              *event = NULL;

        if (this_xl == NULL)
                return -1;

        if (this_xl->options == NULL)
                return -1;

        ctx = this_xl->ctx;
        if (!ctx)
                return -1;


        set_fuse_xlator(this_xl);

        options = this_xl->options;

        if (this_xl->name == NULL) {
                this_xl->name = gf_strdup ("fuse");
                if (!this_xl->name) {
                        gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                "Out of memory");

                        goto cleanup_exit;
                }
                xl_name_allocated = 1;
        }

        priv = GF_CALLOC (1, sizeof (*priv), gf_fuse_mt_fuse_private_t);
        if (!priv) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "Out of memory");

                goto cleanup_exit;
        }
        this_xl->private = (void *) priv;
        priv->mount_point = NULL;

        INIT_LIST_HEAD (&priv->invalidate_list);
        pthread_cond_init (&priv->invalidate_cond, NULL);
        pthread_mutex_init (&priv->invalidate_mutex, NULL);

        /* get options from option dictionary */
        ret = dict_get_str (options, ZR_MOUNTPOINT_OPT, &value_string);
        if (ret == -1 || value_string == NULL) {
                gf_log ("fuse", GF_LOG_ERROR,
                        "Mandatory option 'mountpoint' is not specified.");
                goto cleanup_exit;
        }

        if (stat (value_string, &stbuf) != 0) {
                if (errno == ENOENT) {
                        gf_log (this_xl->name, GF_LOG_ERROR,
                                "%s %s does not exist",
                                ZR_MOUNTPOINT_OPT, value_string);
                } else if (errno == ENOTCONN) {
                        gf_log (this_xl->name, GF_LOG_ERROR,
                                "Mountpoint %s seems to have a stale "
                                "mount, run 'umount %s' and try again.",
                                value_string, value_string);
                } else {
                        gf_log (this_xl->name, GF_LOG_DEBUG,
                                "%s %s : stat returned %s",
                                ZR_MOUNTPOINT_OPT,
                                value_string, strerror (errno));
                }
                goto cleanup_exit;
        }

        if (S_ISDIR (stbuf.st_mode) == 0) {
                gf_log (this_xl->name, GF_LOG_ERROR,
                        "%s %s is not a directory",
                        ZR_MOUNTPOINT_OPT, value_string);
                goto cleanup_exit;
        }
        priv->mount_point = gf_strdup (value_string);
        if (!priv->mount_point) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "Out of memory");

                goto cleanup_exit;
        }

        GF_OPTION_INIT (ZR_ATTR_TIMEOUT_OPT, priv->attribute_timeout, double,
                        cleanup_exit);

        GF_OPTION_INIT (ZR_ENTRY_TIMEOUT_OPT, priv->entry_timeout, double,
                        cleanup_exit);

        GF_OPTION_INIT (ZR_NEGATIVE_TIMEOUT_OPT, priv->negative_timeout, double,
                        cleanup_exit);

        GF_OPTION_INIT ("client-pid", priv->client_pid, int32, cleanup_exit);
        /* have to check & register the presence of client-pid manually */
        priv->client_pid_set = !!dict_get (this_xl->options, "client-pid");

        GF_OPTION_INIT ("uid-map-root", priv->uid_map_root, uint32,
                        cleanup_exit);

        priv->direct_io_mode = 2;
        ret = dict_get_str (options, ZR_DIRECT_IO_OPT, &value_string);
        if (ret == 0) {
                ret = gf_string2boolean (value_string, &priv->direct_io_mode);
                GF_ASSERT (ret == 0);
        }

        GF_OPTION_INIT (ZR_STRICT_VOLFILE_CHECK, priv->strict_volfile_check,
                        bool, cleanup_exit);

        GF_OPTION_INIT ("acl", priv->acl, bool, cleanup_exit);

        if (priv->uid_map_root)
                priv->acl = 1;

        GF_OPTION_INIT ("selinux", priv->selinux, bool, cleanup_exit);

        GF_OPTION_INIT ("capability", priv->capability, bool, cleanup_exit);

        GF_OPTION_INIT ("read-only", priv->read_only, bool, cleanup_exit);

        GF_OPTION_INIT ("enable-ino32", priv->enable_ino32, bool, cleanup_exit);

        GF_OPTION_INIT ("use-readdirp", priv->use_readdirp, bool, cleanup_exit);

        priv->fuse_dump_fd = -1;
        ret = dict_get_str (options, "dump-fuse", &value_string);
        if (ret == 0) {
                ret = unlink (value_string);
                if (ret != -1 || errno == ENOENT)
                        ret = open (value_string, O_RDWR|O_CREAT|O_EXCL,
                                    S_IRUSR|S_IWUSR);
                if (ret == -1) {
                        gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                "cannot open fuse dump file %s",
                                 value_string);

                        goto cleanup_exit;
                }
                priv->fuse_dump_fd = ret;
        }

        sync_to_mount = _gf_false;
        ret = dict_get_str (options, "sync-to-mount", &value_string);
        if (ret == 0) {
                ret = gf_string2boolean (value_string,
                                         &sync_to_mount);
                GF_ASSERT (ret == 0);
        }

	priv->fopen_keep_cache = 2;
	if (dict_get (options, "fopen-keep-cache")) {
		GF_OPTION_INIT("fopen-keep-cache", fopen_keep_cache, bool,
			       cleanup_exit);
		priv->fopen_keep_cache = fopen_keep_cache;
	}

        GF_OPTION_INIT("gid-timeout", priv->gid_cache_timeout, int32,
                cleanup_exit);

        GF_OPTION_INIT ("fuse-mountopts", priv->fuse_mountopts, str, cleanup_exit);

        if (gid_cache_init(&priv->gid_cache, priv->gid_cache_timeout) < 0) {
                gf_log("glusterfs-fuse", GF_LOG_ERROR, "Failed to initialize "
                        "group cache.");
                goto cleanup_exit;
        }

        GF_OPTION_INIT("resolve-gids", priv->resolve_gids, bool, cleanup_exit);

        /* default values seemed to work fine during testing */
        GF_OPTION_INIT ("background-qlen", priv->background_qlen, int32,
                        cleanup_exit);
        GF_OPTION_INIT ("congestion-threshold", priv->congestion_threshold,
                        int32, cleanup_exit);

        GF_OPTION_INIT("no-root-squash", priv->no_root_squash, bool,
                       cleanup_exit);
        /* change the client_pid to no-root-squash pid only if the
           client is none of defrag process, hadoop access and gsyncd process.
        */
        if (!priv->client_pid_set) {
                if (priv->no_root_squash == _gf_true) {
                        priv->client_pid_set = _gf_true;
                        priv->client_pid = GF_CLIENT_PID_NO_ROOT_SQUASH;
                }
        }

        /* user has set only background-qlen, not congestion-threshold,
           use the fuse kernel driver formula to set congestion. ie, 75% */
        if (dict_get (this_xl->options, "background-qlen") &&
            !dict_get (this_xl->options, "congestion-threshold")) {
                priv->congestion_threshold = (priv->background_qlen * 3) / 4;
                gf_log (this_xl->name, GF_LOG_INFO,
                        "setting congestion control as 75%% of "
                        "background-queue length (ie, (.75 * %d) = %d",
                        priv->background_qlen, priv->congestion_threshold);
        }

        /* congestion should not be higher than background queue length */
        if (priv->congestion_threshold > priv->background_qlen) {
                gf_log (this_xl->name, GF_LOG_INFO,
                        "setting congestion control same as "
                        "background-queue length (%d)",
                        priv->background_qlen);
                priv->congestion_threshold = priv->background_qlen;
        }

        cmd_args = &this_xl->ctx->cmd_args;
        fsname = cmd_args->volfile;
        if (!fsname && cmd_args->volfile_server) {
                if (cmd_args->volfile_id) {
                        fsname = GF_MALLOC (
                                   strlen (cmd_args->volfile_server) + 1 +
                                   strlen (cmd_args->volfile_id) + 1,
                                   gf_fuse_mt_fuse_private_t);
                        if (!fsname) {
                                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                                        "Out of memory");
                                goto cleanup_exit;
                        }
                        fsname_allocated = 1;
                        strcpy (fsname, cmd_args->volfile_server);
                        strcat (fsname, ":");
                        strcat (fsname, cmd_args->volfile_id);
                } else
                        fsname = cmd_args->volfile_server;
        }
        if (!fsname)
                fsname = "glusterfs";

        priv->fdtable = gf_fd_fdtable_alloc ();
        if (priv->fdtable == NULL) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR, "Out of memory");
                goto cleanup_exit;
        }

        if (priv->read_only)
                mntflags |= MS_RDONLY;
        gf_asprintf (&mnt_args, "%s%s%sallow_other,max_read=131072",
                     priv->acl ? "" : "default_permissions,",
                     priv->fuse_mountopts ? priv->fuse_mountopts : "",
                     priv->fuse_mountopts ? "," : "");
        if (!mnt_args)
                goto cleanup_exit;

        if (pipe(priv->status_pipe) < 0) {
                gf_log (this_xl->name, GF_LOG_ERROR,
                        "could not create pipe to separate mount process");
                goto cleanup_exit;
        }

#ifdef NEVER
        mnt_data = (struct mount_data *) MALLOC (sizeof(struct mount_data));
        if (!mnt_data) {
                gf_log ("glusterfs-fuse", GF_LOG_ERROR,
                        "Out of memory");
                goto cleanup_exit;
        }
        mount_data_allocated = 1;
        mnt_data->private = priv;
        mnt_data->mountpoint = priv->mount_point;
        mnt_data->fsname = fsname;
        mnt_data->mountflags = mntflags;
        mnt_data->mnt_param = mntflags;
        mnt_data->status_fd = priv->status_pipe[1];

        ret = gf_thread_create (&priv->fuse_thread, NULL,
        			mount_proc, mnt_data);
        if (ret != 0) {
                gf_log (this_xl->name, GF_LOG_DEBUG,
                        "pthread_create() failed (%s)",
                        strerror (errno));
                goto cleanup_exit;
        }
#endif /* NEVER */

        event = eh_new (FUSE_EVENT_HISTORY_SIZE, _gf_false, NULL);
        if (!event) {
                gf_log (this_xl->name, GF_LOG_ERROR,
                        "could not create a new event history");
                goto cleanup_exit;
        }

        this_xl->history = event;

        pthread_mutex_init (&priv->fuse_dump_mutex, NULL);
        pthread_cond_init (&priv->sync_cond, NULL);
        pthread_mutex_init (&priv->sync_mutex, NULL);
        priv->event_recvd = 0;

        for (i = 0; i < FUSE_OP_HIGH; i++) {
                if (!fuse_std_ops[i])
                        fuse_std_ops[i] = fuse_enosys;
                if (!fuse_dump_ops[i])
                        fuse_dump_ops[i] = fuse_dumper;
        }
        priv->fuse_ops = fuse_std_ops;
        if (priv->fuse_dump_fd != -1) {
                priv->fuse_ops0 = priv->fuse_ops;
                priv->fuse_ops  = fuse_dump_ops;
        }

        if (fsname_allocated)
                GF_FREE (fsname);
        GF_FREE (mnt_args);
        return 0;

cleanup_exit:
        if (xl_name_allocated)
                GF_FREE (this_xl->name);
        if (fsname_allocated)
                GF_FREE (fsname);
        if (priv) {
                GF_FREE (priv->mount_point);
                if (priv->fuse_dump_fd != -1)
                        close (priv->fuse_dump_fd);
                GF_FREE (priv);
        }
        return -1;
}


void
fini (xlator_t *this_xl)
{
        fuse_private_t *priv = NULL;
        char *mount_point = NULL;

        if (this_xl == NULL)
                return;

        if ((priv = this_xl->private) == NULL)
                return;

        pthread_mutex_lock (&priv->sync_mutex);
        {
                if (!(priv->fini_invoked)) {
                        priv->fini_invoked = _gf_true;
                } else {
                        pthread_mutex_unlock (&priv->sync_mutex);
                        return;
                }
        }
        pthread_mutex_unlock (&priv->sync_mutex);

        if (dict_get (this_xl->options, ZR_MOUNTPOINT_OPT))
                mount_point = data_to_str (dict_get (this_xl->options,
                                                     ZR_MOUNTPOINT_OPT));
        if (mount_point != NULL) {
                gf_log (this_xl->name, GF_LOG_INFO,
                        "Unmounting '%s'.", mount_point);

                // TODO: umount and release the mount thread,
                gf_fuse_unmount (mount_point, -1);
                close (priv->fuse_dump_fd);
                dict_del (this_xl->options, ZR_MOUNTPOINT_OPT);
        }
        /* Process should terminate once fuse xlator is finished.
         * Required for AUTH_FAILED event.
         */
        kill (getpid (), SIGTERM);
}

struct xlator_fops fops;

struct xlator_cbks cbks = {
};


struct xlator_dumpops dumpops = {
        .priv  = fuse_priv_dump,
        .inode = fuse_itable_dump,
        .history = fuse_history_dump,
};

struct volume_options options[] = {
        { .key  = {"direct-io-mode"},
          .type = GF_OPTION_TYPE_BOOL
        },
        { .key  = {ZR_MOUNTPOINT_OPT, "mount-point"},
          .type = GF_OPTION_TYPE_PATH
        },
        { .key  = {ZR_DUMP_FUSE, "fuse-dumpfile"},
          .type = GF_OPTION_TYPE_PATH
        },
        { .key  = {ZR_ATTR_TIMEOUT_OPT},
          .type = GF_OPTION_TYPE_DOUBLE,
          .default_value = "1.0"
        },
        { .key  = {ZR_ENTRY_TIMEOUT_OPT},
          .type = GF_OPTION_TYPE_DOUBLE,
          .default_value = "1.0"
        },
        { .key  = {ZR_NEGATIVE_TIMEOUT_OPT},
          .type = GF_OPTION_TYPE_DOUBLE,
          .default_value = "0.0"
        },
        { .key  = {ZR_STRICT_VOLFILE_CHECK},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key  = {"client-pid"},
          .type = GF_OPTION_TYPE_INT
        },
        { .key  = {"uid-map-root"},
          .type = GF_OPTION_TYPE_INT
        },
        { .key  = {"sync-to-mount"},
          .type = GF_OPTION_TYPE_BOOL
        },
        { .key = {"read-only"},
          .type = GF_OPTION_TYPE_BOOL
        },
        { .key = {"fopen-keep-cache"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key = {"gid-timeout"},
          .type = GF_OPTION_TYPE_INT,
          .default_value = "300"
        },
        { .key = {"resolve-gids"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key = {"acl"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key = {"selinux"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key = {"enable-ino32"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key  = {"background-qlen"},
          .type = GF_OPTION_TYPE_INT,
          .default_value = "64",
          .min = 16,
          .max = (64 * GF_UNIT_KB),
        },
        { .key  = {"congestion-threshold"},
          .type = GF_OPTION_TYPE_INT,
          .default_value = "48",
          .min = 12,
          .max = (64 * GF_UNIT_KB),
        },
        { .key = {"fuse-mountopts"},
          .type = GF_OPTION_TYPE_STR
        },
        { .key = {"use-readdirp"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "yes"
        },
        { .key = {"no-root-squash"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false",
          .description = "This is the mount option for disabling the "
          "root squash for the client irrespective of whether the root-squash "
          "option for the volume is set or not. But this option is honoured "
          "only for the trusted clients. For non trusted clients this value "
          "does not have any affect and the volume option for root-squash is "
          "honoured.",
        },
        { .key = {"capability"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "false"
        },
        { .key = {NULL} },
};
