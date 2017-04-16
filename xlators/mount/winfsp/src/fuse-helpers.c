/*
   Copyright (c) 2016 StorSwift, Inc.
   Wang Yi wangyi8848@gmail.com
*/

#include <fuse.h>
#include <grp.h>
#include <pwd.h>

#include "fuse-bridge.h"

static void
fuse_resolve_wipe (fuse_resolve_t* resolve)
{
        SH_FREE ((void*)resolve->path);

        SH_FREE ((void*)resolve->bname);

        if (resolve->fd)
                fd_unref (resolve->fd);

        loc_wipe (&resolve->resolve_loc);

        if (resolve->hint) {
                inode_unref (resolve->hint);
                resolve->hint = 0;
        }

        if (resolve->parhint) {
                inode_unref (resolve->parhint);
                resolve->parhint = 0;
        }
}

void
free_fuse_state (fuse_state_t* state)
{
        xlator_t* this = NULL;
        fuse_private_t* priv = NULL;
        uint64_t winds = 0;
        char switched = 0;

        this = state->this;

        priv = this->private;

        loc_wipe (&state->loc);

        loc_wipe (&state->loc2);

        if (state->xdata) {
                dict_unref (state->xdata);
                state->xdata = (void*)0xaaaaeeee;
        }
        if (state->xattr)
                dict_unref (state->xattr);

        if (state->name) {
                SH_FREE (state->name);
                state->name = NULL;
        }
        if (state->fd) {
                fd_unref (state->fd);
                state->fd = (void*)0xfdfdfdfd;
        }
        if (state->finh) {
                SH_FREE (state->finh);
                state->finh = NULL;
        }

        fuse_resolve_wipe (&state->resolve);
        fuse_resolve_wipe (&state->resolve2);

        pthread_mutex_lock (&priv->sync_mutex);
        {
                winds = --state->active_subvol->winds;
                switched = state->active_subvol->switched;
        }
        pthread_mutex_unlock (&priv->sync_mutex);

        if ((winds == 0) && (switched)) {
                xlator_notify (state->active_subvol, GF_EVENT_PARENT_DOWN,
                               state->active_subvol, NULL);
        }

#ifdef DEBUG
        memset (state, 0x90, sizeof (*state));
#endif
        SH_FREE (state);
        state = NULL;
}

fuse_state_t*
get_fuse_state (xlator_t* this, fuse_in_header_t* finh)
{
        fuse_state_t* state = NULL;
        xlator_t* active_subvol = NULL;
        fuse_private_t* priv = NULL;

        state = (void*)SH_CALLOC (1, sizeof (*state), gf_fuse_mt_fuse_state_t);
        if (!state)
                return NULL;

        state->this = get_fuse_xlator ();
        priv = this->private;

        pthread_mutex_lock (&priv->sync_mutex);
        {
                active_subvol = fuse_active_subvol (state->this);
                active_subvol->winds++;
        }
        pthread_mutex_unlock (&priv->sync_mutex);

        state->active_subvol = active_subvol;
        state->itable = active_subvol->itable;
        state->pool = this->ctx->pool;
        state->finh = finh;
        state->this = this;
        state->stub = NULL;

        LOCK_INIT (&state->lock);

        return state;
}

#define FUSE_MAX_AUX_GROUPS                                                    \
        32 /* We can get only up to 32 aux groups from /proc */
void
frame_fill_groups (call_frame_t* frame)
{
#if defined(GF_LINUX_HOST_OS)
        xlator_t* this = frame->this;
        fuse_private_t* priv = this->private;
        char filename[32];
        char line[4096];
        char* ptr = NULL;
        FILE* fp = NULL;
        int idx = 0;
        long int id = 0;
        char* saveptr = NULL;
        char* endptr = NULL;
        int ret = 0;
        int ngroups = FUSE_MAX_AUX_GROUPS;
        gid_t mygroups[GF_MAX_AUX_GROUPS];

        if (priv->resolve_gids) {
                struct passwd pwent;
                char mystrs[1024];
                struct passwd* result;

                if (getpwuid_r (frame->root->uid, &pwent, mystrs,
                                sizeof (mystrs), &result) != 0) {
                        gf_log (this->name, GF_LOG_ERROR, "getpwuid_r(%u) "
                                                          "failed",
                                frame->root->uid);
                        return;
                }

                ngroups = GF_MAX_AUX_GROUPS;
                if (getgrouplist (result->pw_name, frame->root->gid, mygroups,
                                  &ngroups) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not map %s to "
                                "group list (ngroups %d, max %d)",
                                result->pw_name, ngroups, GF_MAX_AUX_GROUPS);
                        return;
                }

                if (call_stack_alloc_groups (frame->root, ngroups) != 0)
                        goto out;

                /* Copy data to the frame. */
                for (idx = 0; idx < ngroups; ++idx) {
                        frame->root->groups[idx] = mygroups[idx];
                }
                frame->root->ngrps = ngroups;
        } else {
                ret = snprintf (filename, sizeof filename, "/proc/%d/status",
                                frame->root->pid);
                if (ret >= sizeof filename)
                        goto out;

                fp = fopen (filename, "r");
                if (!fp)
                        goto out;

                if (call_stack_alloc_groups (frame->root, ngroups) != 0)
                        goto out;

                while ((ptr = fgets (line, sizeof line, fp))) {
                        if (strncmp (ptr, "Groups:", 7) != 0)
                                continue;

                        ptr = line + 8;

                        for (ptr = strtok_r (ptr, " \t\r\n", &saveptr); ptr;
                             ptr = strtok_r (NULL, " \t\r\n", &saveptr)) {
                                errno = 0;
                                id = strtol (ptr, &endptr, 0);
                                if (errno == ERANGE)
                                        break;
                                if (!endptr || *endptr)
                                        break;
                                frame->root->groups[idx++] = id;
                                if (idx == FUSE_MAX_AUX_GROUPS)
                                        break;
                        }

                        frame->root->ngrps = idx;
                        break;
                }
        }

out:
        if (fp)
                fclose (fp);
#elif defined(GF_SOLARIS_HOST_OS)
        char filename[32];
        char scratch[128];
        prcred_t* prcred = (prcred_t*)scratch;
        FILE* fp = NULL;
        int ret = 0;
        int ngrps;

        ret = snprintf (filename, sizeof filename, "/proc/%d/cred",
                        frame->root->pid);

        if (ret < sizeof filename) {
                fp = fopen (filename, "r");
                if (fp != NULL) {
                        if (fgets (scratch, sizeof scratch, fp) != NULL) {
                                ngrps =
                                  MIN (prcred->pr_ngroups, FUSE_MAX_AUX_GROUPS);
                                if (call_stack_alloc_groups (frame->root,
                                                             ngrps) != 0)
                                        return;
                        }
                        fclose (fp);
                }
        }
#elif defined(CTL_KERN) /* DARWIN and *BSD */
        /*
           N.B. CTL_KERN is an enum on Linux. (Meaning, if it's not
           obvious, that it's not subject to preprocessor directives
           like '#if defined'.)
           Unlike Linux, on Mac OS and the BSDs it is a #define. We
           could test to see that KERN_PROC is defined, but, barring any
           evidence to the contrary, I think that's overkill.
           We might also test that GF_DARWIN_HOST_OS is defined, why
           limit this to just Mac OS. It's equally valid for the BSDs
           and we do have people building on NetBSD and FreeBSD.
        */
        int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, frame->root->pid };
        size_t namelen = sizeof name / sizeof name[0];
        struct kinfo_proc kp;
        size_t kplen = sizeof (kp);
        int i, ngroups;

        if (sysctl (name, namelen, &kp, &kplen, NULL, 0) != 0)
                return;
        ngroups = MIN (kp.kp_eproc.e_ucred.cr_ngroups, NGROUPS_MAX);
        if (call_stack_alloc_groups (frame->root, ngroups) != 0)
                return;
        for (i = 0; i < ngroups; i++)
                frame->root->groups[i] = kp.kp_eproc.e_ucred.cr_groups[i];
        frame->root->ngrps = ngroups;
#elif defined(GF_CYGWIN_HOST_OS)
        // TODO:
        frame->root->ngrps = 0;
#else
        frame->root->ngrps = 0;
#endif /* GF_LINUX_HOST_OS */
}

/*
 * Get the groups for the PID associated with this frame. If enabled,
 * use the gid cache to reduce group list collection.
 */
static void
get_groups (fuse_private_t* priv, call_frame_t* frame)
{
        int i;
        const gid_list_t* gl;
        gid_list_t agl;

        if (!priv || !priv->gid_cache_timeout) {
                frame_fill_groups (frame);
                return;
        }

        if (-1 == priv->gid_cache_timeout) {
                frame->root->ngrps = 0;
                return;
        }

        gl = gid_cache_lookup (&priv->gid_cache, frame->root->pid,
                               frame->root->uid, frame->root->gid);
        if (gl) {
                if (call_stack_alloc_groups (frame->root, gl->gl_count) != 0)
                        return;
                frame->root->ngrps = gl->gl_count;
                for (i = 0; i < gl->gl_count; i++)
                        frame->root->groups[i] = gl->gl_list[i];
                gid_cache_release (&priv->gid_cache, gl);
                return;
        }

        frame_fill_groups (frame);

        agl.gl_id = frame->root->pid;
        agl.gl_uid = frame->root->uid;
        agl.gl_gid = frame->root->gid;
        agl.gl_count = frame->root->ngrps;
        agl.gl_list =
          GF_CALLOC (frame->root->ngrps, sizeof (gid_t), gf_fuse_mt_gids_t);
        if (!agl.gl_list)
                return;

        for (i = 0; i < frame->root->ngrps; i++)
                agl.gl_list[i] = frame->root->groups[i];

        if (gid_cache_add (&priv->gid_cache, &agl) != 1)
                GF_FREE (agl.gl_list);
}

call_frame_t*
get_call_frame_for_req (fuse_state_t* state)
{
        call_pool_t* pool = NULL;
        fuse_in_header_t* finh = NULL;
        call_frame_t* frame = NULL;
        xlator_t* this = NULL;
        fuse_private_t* priv = NULL;

        pool = state->pool;
        finh = state->finh;
        this = state->this;
        priv = this->private;

        frame = create_frame (this, pool);
        if (!frame)
                return NULL;

        if (finh) {
                frame->root->uid = finh->uid;
                frame->root->gid = finh->gid;
                frame->root->pid = finh->pid;
                frame->root->unique = finh->unique;
                set_lk_owner_from_uint64 (&frame->root->lk_owner,
                                          state->lk_owner);
        }

        get_groups (priv, frame);

        if (priv && priv->client_pid_set)
                frame->root->pid = priv->client_pid;

        frame->root->type = GF_OP_TYPE_FOP;

        return frame;
}

inode_t*
fuse_ino_to_inode (uint64_t ino, xlator_t* fuse)
{
        inode_t* inode = NULL;
        xlator_t* active_subvol = NULL;

        if (ino == 1) {
                active_subvol = fuse_active_subvol (fuse);
                if (active_subvol)
                        inode = active_subvol->itable->root;
        } else {
                inode = (inode_t*)(unsigned long)ino;
                inode_ref (inode);
        }

        return inode;
}

uint64_t
inode_to_fuse_nodeid (inode_t* inode)
{
        if (!inode)
                return 0;
        if (__is_root_gfid (inode->gfid))
                return 1;

        return (unsigned long)inode;
}

GF_MUST_CHECK int32_t
fuse_loc_fill (loc_t* loc, fuse_state_t* state, ino_t ino, ino_t par,
               const char* name)
{
        inode_t* inode = NULL;
        inode_t* parent = NULL;
        int32_t ret = -1;
        char* path = NULL;
        uuid_t null_gfid = {
                0,
        };

        /* resistance against multiple invocation of loc_fill not to get
           reference leaks via inode_search() */

        if (name) {
                parent = loc->parent;
                if (!parent) {
                        parent = fuse_ino_to_inode (par, state->this);
                        loc->parent = parent;
                        if (parent)
                                gf_uuid_copy (loc->pargfid, parent->gfid);
                }

                inode = loc->inode;
                if (!inode && parent) {
                        inode = inode_grep (parent->table, parent, name);
                        if (inode) {
                                gf_uuid_copy (loc->gfid, inode->gfid);
                        }
                        loc->inode = inode;
                }

                ret = inode_path (parent, name, &path);
                if (ret <= 0) {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "inode_path failed for %s/%s",
                                (parent) ? uuid_utoa (parent->gfid) : "0",
                                name);
                        goto fail;
                }
                loc->path = path;
        } else {
                inode = loc->inode;
                if (!inode) {
                        inode = fuse_ino_to_inode (ino, state->this);
                        loc->inode = inode;
                        if (inode)
                                gf_uuid_copy (loc->gfid, inode->gfid);
                }

                parent = loc->parent;
                if (!parent) {
                        parent = inode_parent (inode, null_gfid, NULL);
                        loc->parent = parent;
                        if (parent)
                                gf_uuid_copy (loc->pargfid, parent->gfid);
                }

                ret = inode_path (inode, NULL, &path);
                if (ret <= 0) {
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "inode_path failed for %s",
                                (inode) ? uuid_utoa (inode->gfid) : "0");
                        goto fail;
                }
                loc->path = path;
        }

        if (loc->path) {
                loc->name = strrchr (loc->path, '/');
                if (loc->name)
                        loc->name++;
                else
                        loc->name = "";
        }

        if ((ino != 1) && (parent == NULL)) {
                gf_log ("fuse-bridge", GF_LOG_DEBUG,
                        "failed to search parent for %" PRId64 "/%s (%" PRId64
                        ")",
                        (ino_t)par, name, (ino_t)ino);
                ret = -1;
                goto fail;
        }
        ret = 0;
fail:
        /* this should not happen as inode_path returns -1 when buf is NULL
           for sure */
        if (path && !loc->path)
                SH_FREE (path);
        return ret;
}

/* courtesy of folly */
void
gf_fuse_stat2attr (struct iatt* st, struct fuse_attr* fa,
                   gf_boolean_t enable_ino32)
{
        if (enable_ino32)
                fa->ino = GF_FUSE_SQUASH_INO (st->ia_ino);
        else
                fa->ino = st->ia_ino;

        fa->size = st->ia_size;
        fa->blocks = st->ia_blocks;
        fa->atime = st->ia_atime;
        fa->mtime = st->ia_mtime;
        fa->ctime = st->ia_ctime;
        fa->atimensec = st->ia_atime_nsec;
        fa->mtimensec = st->ia_mtime_nsec;
        fa->ctimensec = st->ia_ctime_nsec;
        fa->mode = st_mode_from_ia (st->ia_prot, st->ia_type);
        fa->nlink = st->ia_nlink;
        fa->uid = st->ia_uid;
        fa->gid = st->ia_gid;
        fa->rdev = makedev (ia_major (st->ia_rdev), ia_minor (st->ia_rdev));
#if FUSE_KERNEL_MINOR_VERSION >= 9
        fa->blksize = st->ia_blksize;
#endif
#ifdef GF_DARWIN_HOST_OS
        fa->crtime = (uint64_t)-1;
        fa->crtimensec = (uint32_t)-1;
        fa->flags = 0;
#endif
}

void
gf_fuse_stat2winstat (struct iatt* st, struct fuse_stat* stbuf)
{
        stbuf->st_dev = st->ia_dev;
        stbuf->st_ino = st->ia_ino;
        stbuf->st_mode = st_mode_from_ia (st->ia_prot, st->ia_type);
        stbuf->st_nlink = st->ia_nlink;
        stbuf->st_uid = st->ia_uid;
        stbuf->st_gid = st->ia_gid;
        stbuf->st_rdev =
          makedev (ia_major (st->ia_rdev), ia_minor (st->ia_rdev));
        stbuf->st_size = st->ia_size;
        stbuf->st_atim.tv_sec = st->ia_atime;
        stbuf->st_atim.tv_nsec = st->ia_atime_nsec;
        stbuf->st_mtim.tv_sec = st->ia_mtime;
        stbuf->st_mtim.tv_nsec = st->ia_mtime_nsec;
        stbuf->st_ctim.tv_sec = st->ia_ctime;
        stbuf->st_ctim.tv_nsec = st->ia_ctime_nsec;

        stbuf->st_blksize = st->ia_blksize;
        stbuf->st_blocks = st->ia_blocks;
        stbuf->st_birthtim.tv_sec = -1;
        stbuf->st_birthtim.tv_nsec = -1;
}

void
gf_fuse_attr2winstat (struct fuse_attr* fa, struct stat* stbuf)
{
        stbuf->st_dev = fa->rdev;
        stbuf->st_ino = fa->ino;
        stbuf->st_mode = fa->mode;
        stbuf->st_nlink = fa->nlink;
        stbuf->st_uid = fa->uid;
        stbuf->st_gid = fa->gid;
        stbuf->st_rdev = fa->rdev;
        stbuf->st_size = fa->size;
        stbuf->st_atim.tv_sec = fa->atime;
        stbuf->st_atim.tv_nsec = fa->atimensec;
        stbuf->st_mtim.tv_sec = fa->mtime;
        stbuf->st_mtim.tv_nsec = fa->mtimensec;
        stbuf->st_ctim.tv_sec = fa->ctime;
        stbuf->st_ctim.tv_nsec = fa->ctimensec;

        stbuf->st_blksize = fa->blksize;
        stbuf->st_blocks = fa->blocks;
        stbuf->st_birthtim.tv_sec = -1;
        stbuf->st_birthtim.tv_nsec = -1;
}

void
gf_fuse_fill_dirent (gf_dirent_t* entry, struct fuse_dirent* fde,
                     gf_boolean_t enable_ino32)
{
        if (enable_ino32)
                fde->ino = GF_FUSE_SQUASH_INO (entry->d_ino);
        else
                fde->ino = entry->d_ino;

        fde->off = entry->d_off;
        fde->type = entry->d_type;
        fde->namelen = strlen (entry->d_name);
        strncpy (fde->name, entry->d_name, fde->namelen);
}

void
gf_fuse_dirent2winstat (struct fuse_dirent* ent, struct stat* stbuf)
{
        stbuf->st_ino = ent->ino;
        stbuf->st_mode = ent->type << 12;
}

static int
fuse_do_flip_xattr_ns (char* okey, const char* nns, char** nkey)
{
        int ret = 0;
        char* key = NULL;

        okey = strchr (okey, '.');
        GF_ASSERT (okey);

        key =
          SH_CALLOC (1, strlen (nns) + strlen (okey) + 1, gf_common_mt_char);
        if (!key) {
                ret = -1;
                goto out;
        }

        strcpy (key, nns);
        strcat (key, okey);

        *nkey = key;

out:
        return ret;
}

static int
fuse_xattr_alloc_default (char* okey, char** nkey)
{
        int ret = 0;

        *nkey = sh_strdup (okey);
        if (!*nkey)
                ret = -1;
        return ret;
}

#define PRIV_XA_NS "trusted"
#define UNPRIV_XA_NS "system"

int
fuse_flip_xattr_ns (fuse_private_t* priv, char* okey, char** nkey)
{
        int ret = 0;
        gf_boolean_t need_flip = _gf_false;

        switch (priv->client_pid) {
                case GF_CLIENT_PID_GSYNCD:
                        /* valid xattr(s): *xtime, volume-mark* */
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "PID: %d, checking xattr(s): "
                                "volume-mark*, *xtime",
                                priv->client_pid);
                        if ((strcmp (okey, UNPRIV_XA_NS
                                     ".glusterfs.volume-mark") == 0) ||
                            (fnmatch (UNPRIV_XA_NS ".glusterfs.volume-mark.*",
                                      okey, FNM_PERIOD) == 0) ||
                            (fnmatch (UNPRIV_XA_NS ".glusterfs.*.xtime", okey,
                                      FNM_PERIOD) == 0))
                                need_flip = _gf_true;
                        break;

                case GF_CLIENT_PID_HADOOP:
                        /* valid xattr(s): pathinfo */
                        gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                                "PID: %d, checking xattr(s): "
                                "pathinfo",
                                priv->client_pid);
                        if (strcmp (okey, UNPRIV_XA_NS ".glusterfs.pathinfo") ==
                            0)
                                need_flip = _gf_true;
                        break;
        }

        if (need_flip) {
                gf_log ("glusterfs-fuse", GF_LOG_DEBUG,
                        "flipping %s to " PRIV_XA_NS " equivalent", okey);
                ret = fuse_do_flip_xattr_ns (okey, PRIV_XA_NS, nkey);
        } else {
                /* if we cannot match, continue with what we got */
                ret = fuse_xattr_alloc_default (okey, nkey);
        }

        return ret;
}

int
fuse_ignore_xattr_set (fuse_private_t* priv, char* key)
{
        int ret = 0;

        /* don't mess with user namespace */
        if (fnmatch ("user.*", key, FNM_PERIOD) == 0)
                goto out;

        if (priv->client_pid != GF_CLIENT_PID_GSYNCD)
                goto out;

        /* trusted NS check */
        if (!((fnmatch ("*.glusterfs.*.xtime", key, FNM_PERIOD) == 0) ||
              (fnmatch ("*.glusterfs.volume-mark", key, FNM_PERIOD) == 0) ||
              (fnmatch ("*.glusterfs.volume-mark.*", key, FNM_PERIOD) == 0) ||
              (fnmatch ("system.posix_acl_access", key, FNM_PERIOD) == 0) ||
              (fnmatch ("glusterfs.gfid.newfile", key, FNM_PERIOD) == 0) ||
              (fnmatch ("*.glusterfs.shard.block-size", key, FNM_PERIOD) ==
               0) ||
              (fnmatch ("*.glusterfs.shard.file-size", key, FNM_PERIOD) == 0)))
                ret = -1;

out:
        gf_log ("glusterfs-fuse", GF_LOG_DEBUG, "%s setxattr: key [%s], "
                                                " client pid [%d]",
                (ret ? "disallowing" : "allowing"), key, priv->client_pid);

        return ret;
}

int
fuse_check_selinux_cap_xattr (fuse_private_t* priv, char* name)
{
        int ret = -1;

        if (strcmp (name, "security.selinux") &&
            strcmp (name, "security.capability")) {
                /* if xattr name is not of interest, no validations needed */
                ret = 0;
                goto out;
        }

        if ((strcmp (name, "security.selinux") == 0) && (priv->selinux)) {
                ret = 0;
        }

        if ((strcmp (name, "security.capability") == 0) &&
            ((priv->capability) || (priv->selinux))) {
                ret = 0;
        }

out:
        return ret;
}

struct fuse_context*
get_fuse_header_in (void)
{
        struct fuse_context* ctx = fuse_get_context ();
        return ctx;
}

uint64_t
get_fuse_op_unique ()
{
        static uint64_t seed = 0;
        return __sync_fetch_and_add (&seed, 1);
}

inode_t*
fuse_inode_from_path (xlator_t* this, char* path, inode_table_t* itable)
{
        inode_t* inode = NULL;

        if (strcmp (path, "/") == 0) {
                xlator_t* active_subvol = fuse_active_subvol (this);
                if (active_subvol) {
                        inode = active_subvol->itable->root;
                        return inode_ref (inode);
                }
        }

        return inode_resolve (itable, path);
}

char*
fuse_path_from_path (xlator_t* this, const char* cpath, inode_table_t* itable)
{
        if (strcmp (cpath, "/") == 0) {
                return "/";
        }

        return inode_resolve_path (itable, cpath);
}

int
split_pathname (char* pathname, char** path, char** basename)
{
        char* p;

        *path = sh_strdup (pathname);
        if (*path == NULL)
                goto fail_out;

        p = strrchr (*path, '/');
        *basename = sh_strdup (p + 1);
        if (*basename == NULL)
                goto fail_out;

        if (p > *path) {
                *p = '\0';
        } else {
                (*path)[1] = '\0';
        }

        return 0;

fail_out:
        if (*path)
                SH_FREE (*path);
        if (*basename)
                SH_FREE (*basename);

        return -1;
}

inode_t*
fuse_inode_from_path2 (xlator_t* this, char* path, inode_table_t* itable)
{
        int ret = -1;
        struct iatt iatt = {
                0,
        };
        inode_t* linked_inode = itable->root;
        loc_t loc = {
                0,
        };
        char* bname = NULL;
        char* save_ptr = NULL;
        uuid_t gfid = {
                0,
        };
        char* tmp_path = NULL;

        tmp_path = sh_strdup (path);
        if (!tmp_path) {
                goto out;
        }

        memset (gfid, 0, 16);
        gfid[15] = 1;

        gf_uuid_copy (loc.pargfid, gfid);
        loc.parent = inode_ref (itable->root);

        bname = strtok_r (tmp_path, "/", &save_ptr);

        /* sending a lookup on parent directory,
         * Eg:  if  path is like /a/b/c/d/e/f/g/
         * then we will send a lookup on a first and then b,c,d,etc
         */

        while (bname) {
                linked_inode = NULL;
                loc.inode = inode_grep (itable, loc.parent, bname);
                if (loc.inode == NULL) {
                        loc.inode = inode_new (itable);
                        if (loc.inode == NULL) {
                                ret = -ENOMEM;
                                goto out;
                        }
                } else {
                        /*
                         * Inode is already populated in the inode table.
                         * Which means we already looked up the inde and
                         * linked with a dentry. So that we will skip
                         * lookup on this entry, and proceed to next.
                         */
                        bname = strtok_r (NULL, "/", &save_ptr);
                        inode_unref (loc.parent);
                        loc.parent = loc.inode;
                        gf_uuid_copy (loc.pargfid, loc.inode->gfid);
                        loc.inode = NULL;
                        continue;
                }

                loc.name = bname;
                ret = loc_path (&loc, bname);

                ret = syncop_lookup (this, &loc, &iatt, NULL, NULL, NULL);
                if (ret) {
                        gf_log (this->name, GF_LOG_INFO,
                                "Healing of path %s failed on subvolume %s for "
                                "directory %s",
                                path, this->name, bname);
                        goto out;
                }

                linked_inode = inode_link (loc.inode, loc.parent, bname, &iatt);
                if (!linked_inode)
                        goto out;

                loc_wipe (&loc);
                gf_uuid_copy (loc.pargfid, linked_inode->gfid);
                loc.inode = NULL;
                loc.parent = linked_inode;

                bname = strtok_r (NULL, "/", &save_ptr);
        }
out:
        inode_ref (linked_inode);
        loc_wipe (&loc);
        SH_FREE (tmp_path);

        return linked_inode;
}
