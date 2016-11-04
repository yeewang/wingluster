
#ifndef _GF_FUSE_BRIDGE_H_
#define _GF_FUSE_BRIDGE_H_

#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <stddef.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <fnmatch.h>
#include <errno.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif /* _CONFIG_H */

#include "glusterfs.h"
#include "logging.h"
#include "xlator.h"
#include "defaults.h"
#include "common-utils.h"
#include "statedump.h"

#include "fuse_kernel.h"
#include "fuse-mem-types.h"

#include "fuse-misc.h"
#include "fuse-mount.h"

#include "list.h"
#include "dict.h"
#include "syncop.h"
#include "gidcache.h"

#include "winfsp-info.h"

#define FUSE_AUTORELEASE        (FUSE_READDIRPLUS + 1)
#define FUSE_WAITMSG            (FUSE_READDIRPLUS + 2)
#define FUSE_OP_HIGH            (FUSE_READDIRPLUS + 3)

#define GLUSTERFS_XATTR_LEN_MAX 65536

typedef struct fuse_in_header fuse_in_header_t;
typedef struct winfsp_msg winfsp_msg_t;
typedef void(fuse_handler_t)(xlator_t* this, winfsp_msg_t* msg);

struct fuse_private
{
        struct fuse             *fuse;
        uint32_t                proto_minor;
        char                    *volfile;
        size_t                  volfile_size;
        char                    *mount_point;
        struct iobuf            *iobuf;
        void                    *outbuf;

        struct list_head        directory;

        pthread_t               fuse_thread;
        pthread_t               mount_thread;

        char                    fuse_thread_started;
        char                    mount_thread_started;

        uint32_t                direct_io_mode;

        double                  entry_timeout;
        double                  negative_timeout;
        double                  attribute_timeout;

        pthread_cond_t          sync_cond;
        pthread_mutex_t         sync_mutex;
        char                    event_recvd;

        char                    init_recvd;

        pthread_cond_t          msg_cond;
        pthread_mutex_t         msg_mutex;
        struct list_head        msg_list;
        struct list_head        wait_list;

        gf_boolean_t            strict_volfile_check;

        fuse_handler_t          **fuse_ops;
        fuse_handler_t          **fuse_ops0;
        pthread_mutex_t         fuse_dump_mutex;
        int                     fuse_dump_fd;

        glusterfs_graph_t       *next_graph;
        xlator_t                *active_subvol;

        pid_t                   client_pid;
        gf_boolean_t            client_pid_set;
        unsigned                uid_map_root;
        gf_boolean_t            acl;
        gf_boolean_t            selinux;
        gf_boolean_t            read_only;
        int32_t                 fopen_keep_cache;
        int32_t                 gid_cache_timeout;
        gf_boolean_t            enable_ino32;
        /* This is the mount option for disabling the root-squash for the
           mount irrespective of whether the root-squash option for the
           volume is set or not. But this option is honoured only for
           thr trusted clients. For non trusted clients this value does
           not have any affect and the volume option for root-squash is
           honoured.
        */
        gf_boolean_t            no_root_squash;
        fdtable_t               *fdtable;
        gid_cache_t             gid_cache;
        char                    *fuse_mountopts;

        /* For fuse-reverse-validation */
        struct list_head        invalidate_list;
        pthread_cond_t          invalidate_cond;
        pthread_mutex_t         invalidate_mutex;
        gf_boolean_t            reverse_fuse_thread_started;

        /* For communicating with separate mount thread. */
        int                     status_pipe[2];

        /* for fuse queue length and congestion threshold */
        int                     background_qlen;
        int                     congestion_threshold;

        /* for using fuse-kernel readdirp*/
        gf_boolean_t            use_readdirp;

        /* fini started, helps prevent multiple epoll worker threads
         * firing up the fini routine */
        gf_boolean_t            fini_invoked;

        /* resolve gid with getgrouplist() instead of /proc/%d/status */
        gf_boolean_t            resolve_gids;

        /* Enable or disable capability support */
        gf_boolean_t            capability;
};
typedef struct fuse_private fuse_private_t;

struct fuse_invalidate_node
{
        gf_boolean_t    is_entry;  /* entry or node */
        uint64_t        unique;
        int             error;
        union {
                uint64_t        parent;
                uint64_t        ino;
        };
        char            name[NAME_MAX];
        struct list_head next;
};
typedef struct fuse_invalidate_node fuse_invalidate_node_t;

struct fuse_graph_switch_args
{
        xlator_t* this;
        xlator_t* old_subvol;
        xlator_t* new_subvol;
};
typedef struct fuse_graph_switch_args fuse_graph_switch_args_t;

#define FUSE_EVENT_HISTORY_SIZE 1024

#define _FH_TO_FD(fh) ((fd_t*)(uintptr_t)(fh))

#define FH_TO_FD(fh) ((fh != INVALIDE_HANDLE) ? (fd_ref(_FH_TO_FD(fh))) : ((fd_t*)0))
#define FD_TO_FH(fd) ((fd != NULL) ? ((uintptr_t)(fd)) : (INVALIDE_HANDLE))

/* Use the same logic as the Linux NFS-client */
#define GF_FUSE_SQUASH_INO(ino) (((uint32_t)ino) ^ (ino >> 32))

#define FUSE_FOP(state, ret, op_num, fop, args...)                             \
        do {                                                                   \
                xlator_t* xl = NULL;                                           \
                call_frame_t* frame = NULL;                                    \
                                                                               \
                xl = state->active_subvol;                                     \
                if (!xl) {                                                     \
                        gf_log_callingfn(state->this->name, GF_LOG_ERROR,      \
                                         "No active subvolume");               \
                        winfsp_send_err(state->this, state->stub, ENOENT);      \
                        free_fuse_state(state);                                \
                        break;                                                 \
                }                                                              \
                                                                               \
                frame = get_call_frame_for_req(state);                         \
                if (!frame) {                                                  \
                        /* This is not completely clean, as some               \
                         * earlier allocations might remain unfreed            \
                         * if we return at this point, but still               \
                         * better than trying to go on with a NULL             \
                         * frame ...                                           \
                         */                                                    \
                        winfsp_send_err(state->this, state->stub, ENOMEM);      \
                        free_fuse_state(state);                                \
                        /* ideally, need to 'return', but let the */           \
                        /* calling function take care of it */                 \
                        break;                                                 \
                }                                                              \
                                                                               \
                frame->root->state = state;                                    \
                frame->root->op = op_num;                                      \
                frame->op = op_num;                                            \
                                                                               \
                if (state->this->history)                                      \
                        gf_log_eh("%" PRIu64 ", %s, path: (%s), gfid: "        \
                                  "(%s)",                                      \
                                  frame->root->unique,                         \
                                  gf_fop_list[frame->root->op],                \
                                  state->loc.path,                             \
                                  (state->fd == NULL)                          \
                                    ? uuid_utoa(state->loc.gfid)               \
                                    : uuid_utoa(state->fd->inode->gfid));      \
                STACK_WIND(frame, ret, xl, xl->fops->fop, args);               \
        } while (0)

#define GF_SELECT_LOG_LEVEL(_errno)                                            \
        (((_errno == ENOENT) || (_errno == ESTALE))?    \
         GF_LOG_DEBUG)

#define FILL_STATE(msg, this, finh, path, state)                               \
        do {                                                                   \
                state = get_fuse_state(this, finh);                            \
                if (!state) {                                                  \
                        gf_log("glusterfs-fuse", GF_LOG_ERROR,                 \
                               "FUSE message unique %" PRIu64 " opcode %d:"    \
                               " state allocation failed",                     \
                               finh->unique, finh->opcode);                    \
                                                                               \
                        winfsp_send_err(this, msg, ENOMEM);                     \
                        GF_FREE(finh);                                         \
                                                                               \
                        return;                                                \
                }                                                              \
                                                                               \
                if (path) {                                                    \
                        inode_t *inode = NULL;                                 \
                                                                               \
                        inode = fuse_inode_from_path(this, path, state->itable);\
                        if (inode == NULL) {                                   \
                                winfsp_send_err(this, msg, ENOENT);             \
                                free_fuse_state(state);                        \
                                                                               \
                                return;                                        \
                        }                                                      \
                        finh->nodeid = inode_to_fuse_nodeid(inode);            \
                        inode_unref(inode);                                    \
                }                                                              \
        } while (0)

#define INIT_FUSE_HEADER(_finh, _unique, _opcode, _ctx)                        \
        do {                                                                   \
                const size_t msg0_size = sizeof(*_finh);                       \
                (_finh) = GF_CALLOC(1, msg0_size, gf_fuse_mt_iov_base);        \
                (_finh)->len = msg0_size;                                      \
                (_finh)->opcode = _opcode;                                     \
                (_finh)->unique = _unique;                                     \
                (_finh)->nodeid = 0;                                           \
                if (_ctx) {                                                    \
                        (_finh)->uid = (_ctx)->uid;                            \
                        (_finh)->gid = (_ctx)->gid;                            \
                        (_finh)->pid = (_ctx)->pid;                            \
                } else {                                                       \
                        (_finh)->uid = 0;                                      \
                        (_finh)->gid = 0;                                      \
                        (_finh)->pid = 0;                                      \
                }                                                              \
        } while (0)

#define FUSE_ENTRY_CREATE(this, priv, finh, state, fci, op)                    \
        do {                                                                   \
                if (priv->proto_minor >= 12)                                   \
                        state->mode &= ~fci->umask;                            \
                if (priv->proto_minor >= 12 && priv->acl) {                    \
                        state->xdata = dict_new();                             \
                        if (!state->xdata) {                                   \
                                gf_log("glusterfs-fuse", GF_LOG_WARNING,       \
                                       "%s failed to allocate "                \
                                       "a param dictionary",                   \
                                       op);                                    \
                                winfsp_send_err(this, state->stub, ENOMEM);     \
                                free_fuse_state(state);                        \
                                return;                                        \
                        }                                                      \
                        state->umask = fci->umask;                             \
                                                                               \
                        /* TODO: remove this after 3.4.0 release. keeping it   \
                           for the                                             \
                           sake of backward compatibility with old (3.3.[01])  \
                           releases till then. */                              \
                        ret =                                                  \
                          dict_set_int16(state->xdata, "umask", fci->umask);   \
                        if (ret < 0) {                                         \
                                gf_log("glusterfs-fuse", GF_LOG_WARNING,       \
                                       "%s Failed adding umask"                \
                                       " to request",                          \
                                       op);                                    \
                                dict_destroy(state->xdata);                    \
                                winfsp_send_err(this, state->stub, ENOMEM);     \
                                free_fuse_state(state);                        \
                                return;                                        \
                        }                                                      \
                        ret = dict_set_int16(state->xdata, "mode", fci->mode); \
                        if (ret < 0) {                                         \
                                gf_log("glusterfs-fuse", GF_LOG_WARNING,       \
                                       "%s Failed adding mode "                \
                                       "to request",                           \
                                       op);                                    \
                                dict_destroy(state->xdata);                    \
                                winfsp_send_err(this, state->stub, ENOMEM);     \
                                free_fuse_state(state);                        \
                                return;                                        \
                        }                                                      \
                }                                                              \
        } while (0)

#define fuse_log_eh_fop(this, state, frame, op_ret, op_errno)                  \
        do {                                                                   \
                if (this->history) {                                           \
                        if (state->fd)                                         \
                                gf_log_eh(                                     \
                                  "op_ret: %d, op_errno: %d, "                 \
                                  "%" PRIu64 ", %s () => %p, gfid: %s",        \
                                  op_ret, op_errno, frame->root->unique,       \
                                  gf_fop_list[frame->root->op], state->fd,     \
                                  uuid_utoa(state->fd->inode->gfid));          \
                        else                                                   \
                                gf_log_eh(                                     \
                                  "op_ret: %d, op_errno: %d, "                 \
                                  "%" PRIu64 ", %s () => %s, gfid: %s",        \
                                  op_ret, op_errno, frame->root->unique,       \
                                  gf_fop_list[frame->root->op],                \
                                  state->loc.path,                             \
                                  uuid_utoa(state->loc.gfid));                 \
                }                                                              \
        } while (0)

#define fuse_log_eh(this, args...)                                             \
        do {                                                                   \
                if (this->history)                                             \
                        gf_log_eh(args);                                       \
        } while (0)

static inline xlator_t*
fuse_active_subvol(xlator_t* fuse)
{
        fuse_private_t* priv = NULL;

        priv = fuse->private;

        return priv->active_subvol;
}

typedef enum {
        RESOLVE_MUST = 1,
        RESOLVE_NOT,
        RESOLVE_MAY,
        RESOLVE_DONTCARE,
        RESOLVE_EXACT
} fuse_resolve_type_t;

typedef struct {
        fuse_resolve_type_t type;
        fd_t* fd;
        char* path;
        char* bname;
        u_char gfid[16];
        inode_t* hint;
        u_char pargfid[16];
        inode_t* parhint;
        int op_ret;
        int op_errno;
        loc_t resolve_loc;
} fuse_resolve_t;

typedef struct winfsp_msg {
        struct list_head list;
        pthread_cond_t cond;
        pthread_mutex_t mutex;
        int type;
        uint64_t unique;
        gf_boolean_t autorelease;
        int fin;
        int ret;
        fuse_in_header_t* finh;
        uint8_t args[0];
} winfsp_msg_t;

typedef struct {
        void* pool;
        xlator_t* this;
        xlator_t* active_subvol;
        inode_table_t* itable;
        loc_t loc;
        loc_t loc2;
        fuse_in_header_t* finh;
        int32_t flags;
        off_t off;
        size_t size;
        unsigned long nlookup;
        fd_t* fd;
        dict_t* xattr;
        dict_t* xdata;
        char* name;
        char is_revalidate;
        gf_boolean_t truncate_needed;
        gf_lock_t lock;
        uint64_t lk_owner;

        /* used within resolve_and_resume */
        /* */
        fuse_resolve_t resolve;
        fuse_resolve_t resolve2;

        loc_t* loc_now;
        fuse_resolve_t* resolve_now;

        void* resume_fn;

        int valid;
        int mask;
        dev_t rdev;
        mode_t mode;
        mode_t umask;
        struct iatt attr;
        struct gf_flock lk_lock;
        struct iovec vector;

        uuid_t gfid;
        uint32_t io_flags;
        int32_t fd_no;

        winfsp_msg_t* stub;
} fuse_state_t;

typedef struct
{
        uint32_t open_flags;
        char migration_failed;
        fd_t* activefd;
} fuse_fd_ctx_t;

typedef void (*fuse_resume_fn_t)(fuse_state_t* state);

GF_MUST_CHECK int32_t fuse_loc_fill(loc_t* loc, fuse_state_t* state, ino_t ino,
                                    ino_t par, const char* name);
call_frame_t* get_call_frame_for_req(fuse_state_t* state);
fuse_state_t* get_fuse_state(xlator_t* this, fuse_in_header_t* finh);
void free_fuse_state(fuse_state_t* state);
void gf_fuse_stat2attr(struct iatt* st, struct fuse_attr* fa,
                       gf_boolean_t enable_ino32);
void gf_fuse_stat2winstat(struct iatt* st, struct fuse_stat* stbuf);
void gf_fuse_attr2winstat(struct fuse_attr* fa, struct stat* stbuf);
void gf_fuse_dirent2winstat(struct fuse_dirent* ent, struct stat* stbuf);

void gf_fuse_fill_dirent(gf_dirent_t* entry, struct fuse_dirent* fde,
                         gf_boolean_t enable_ino32);
uint64_t inode_to_fuse_nodeid(inode_t* inode);
xlator_t* fuse_active_subvol(xlator_t* fuse);
inode_t* fuse_ino_to_inode(uint64_t ino, xlator_t* fuse);
int fuse_gfid_set(fuse_state_t* state);
int fuse_flip_xattr_ns(struct fuse_private* priv, char* okey, char** nkey);
fuse_fd_ctx_t* __fuse_fd_ctx_check_n_create(xlator_t* this, fd_t* fd);
fuse_fd_ctx_t* fuse_fd_ctx_check_n_create(xlator_t* this, fd_t* fd);

int fuse_resolve_fd(fuse_state_t* state);
int fuse_resolve_and_resume(fuse_state_t* state, fuse_resume_fn_t fn);
int fuse_resolve_inode_init(fuse_state_t* state, fuse_resolve_t* resolve,
                            ino_t ino);
int fuse_resolve_entry_init(fuse_state_t* state, fuse_resolve_t* resolve,
                            ino_t par, char* name);
int fuse_resolve_fd_init(fuse_state_t* state, fuse_resolve_t* resolve,
                         fd_t* fd);
int fuse_ignore_xattr_set(fuse_private_t* priv, char* key);
void fuse_fop_resume(fuse_state_t* state);
int dump_history_fuse(circular_buffer_t* cb, void* data);
int fuse_check_selinux_cap_xattr(fuse_private_t* priv, char* name);

xlator_t* get_fuse_xlator();
struct fuse_context* get_fuse_header_in(void);

uint64_t get_fuse_op_unique();
inode_t* fuse_inode_from_path(xlator_t* this, char* path,
        inode_table_t* itable);
char * fuse_path_from_path (xlator_t *this, const char *cpath,
        inode_table_t *itable);
int split_pathname(char *pathname, char **path, char **basename);
char * fuse_get_gf_path(xlator_t* this, const char *path);

const char *create_winpath_from_cygpath(const char *cygpath);

#endif /* _GF_FUSE_BRIDGE_H_ */
