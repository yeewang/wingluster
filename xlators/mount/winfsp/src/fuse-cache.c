/*
  Caching file system proxy
  Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2016  Wang Yi wangyi8848@gmail.com

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse-cache.h"
#include <errno.h>
#include <glib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "list.h"
#include "mem-pool.h"
#include "common-utils.h"


#define DEFAULT_CACHE_TIMEOUT_SECS 20
#define DEFAULT_CACHE_EMPTY_TIMEOUT_SECS 5
#define DEFAULT_CACHE_STAT_TIMEOUT_SECS (5 * 60)
#define DEFAULT_CACHE_DIR_TIMEOUT_SECS 60
#define DEFAULT_CACHE_LINK_TIMEOUT_SECS 20
#define DEFAULT_MAX_CACHE_SIZE (1024 * 1024)
#define DEFAULT_CACHE_CLEAN_INTERVAL_SECS 60
#define DEFAULT_MIN_CACHE_CLEAN_INTERVAL_SECS 5

struct cache
{
        int on;
        unsigned int empty_timeout_secs;
        unsigned int stat_timeout_secs;
        unsigned int dir_timeout_secs;
        unsigned int link_timeout_secs;
        unsigned int max_size;
        unsigned int clean_interval_secs;
        unsigned int min_clean_interval_secs;
        struct fuse_cache_operations* next_oper;
        GHashTable* table;
        uv_mutex_t lock;
        time_t last_cleaned;
        uint64_t write_ctr;
};

static struct cache cache;

struct node
{
        struct fuse_stat stat;
        GList *dir;
        time_t dir_valid;
        char* link;
        time_t link_valid;
        time_t valid;
        int nullpath;
};

struct fuse_cache_dirhandle
{
        const char* path;
        fuse_dirh_t h;
        fuse_dirfil_t filler;
        GList* dir;
        uint64_t wrctr;
};

/* refresh list */

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, field)                                         \
        ((type*)((char*)(ptr) - ((char*)&((type*)0)->field)))
#endif

typedef enum refresh_type {
        RT_dir,
        RT_attr,
} refresh_type_t;

struct cache_refresh_node {
        struct list_head list;
        char* path;
        refresh_type_t type;
};

static struct list_head cache_refresh_list;
uv_cond_t cache_refresh_cond;
uv_mutex_t cache_refresh_lock;

/* end of refresh list */

static void
cache_add_nullpath (const char* path);

static void
cache_node_changed (const char* path);

static void
cache_add_dir (const char* path, GList* dir);

static void
cache_add_path (const char* path, const char* name);

static void
cache_del_path (const char* path, const char* name);

static void
free_dir (GList *dir)
{
        GList *t, *n;
        if (dir) {
                t = dir;
                while (t != NULL) {
                        n = t->next;
                        g_free (t->data);
                        dir = g_list_delete_link (dir, t);
                        t = n;
                }
        }
}

static void
free_node (gpointer node_)
{
        struct node* node = (struct node*)node_;
        free_dir (node->dir);
        g_free (node->link);
        g_free (node);
}

static int
cache_clean_entry (void* key_, struct node* node, time_t* now)
{
        (void)key_;
        if (*now > node->valid)
                return TRUE;
        else
                return FALSE;
}

static void
cache_clean (void)
{
        time_t now = time (NULL);
        if (now > cache.last_cleaned + cache.min_clean_interval_secs &&
            (g_hash_table_size (cache.table) > cache.max_size ||
             now > cache.last_cleaned + cache.clean_interval_secs)) {
                g_hash_table_foreach_remove (cache.table,
                                             (GHRFunc)cache_clean_entry, &now);
                cache.last_cleaned = now;
        }
}

static struct node*
cache_lookup (const char* path)
{
        return (struct node*)g_hash_table_lookup (cache.table, path);
}

static void
cache_purge (const char* path)
{
        g_hash_table_remove (cache.table, path);
}

static void
cache_purge_parent (const char* path)
{
        const char* s = strrchr (path, '/');
        if (s) {
                if (s == path)
                        g_hash_table_remove (cache.table, "/");
                else {
                        char* parent = g_strndup (path, s - path);
                        cache_purge (parent);
                        g_free (parent);
                }
        }
}

static void
cache_dirty_parent (const char* path)
{
        struct node* node = NULL;
        const char* s = strrchr (path, '/');
        if (s) {
                if (s == path) {
                        node = cache_lookup ("/");
                        node->dir_valid  = 0;
                }
                else {
                        char* parent = g_strndup (path, s - path);
                        node = cache_lookup (parent);
                        node->dir_valid  = 0;
                        g_free (parent);
                }
        }
}

static void
cache_touch_parent (const char* path)
{
        struct node* node = NULL;
        const char* s = strrchr (path, '/');
        if (s) {
                if (s == path)
                        node = cache_lookup ("/");
                else {
                        char* parent = g_strndup (path, s - path);
                        node = cache_lookup (parent);
                        g_free (parent);
                }

                if (node) {
                        struct timespec now;
                        clock_gettime (CLOCK_REALTIME, &now);
                        node->stat.st_mtim = now;
                        node->stat.st_atim = now;
                }
        }
}

static void
cache_add_parent (const char* path)
{
        char* parent = NULL;
        struct node* pnode = NULL;
        const char* name;
        const char* s = strrchr (path, '/');
        if (s) {
                if (s == path) {
                        parent = g_strdup ("/");
                        pnode = cache_lookup (parent);
                } else {
                        parent = g_strndup (path, s - path);
                        pnode = cache_lookup (parent);
                }
        }
        name = s + 1;

        if (pnode == NULL) {
                cache_node_changed (path);
                if (parent)
                        g_free (parent);
                return;
        }

        cache_add_path (parent, name);

        /* does not insert self node! */

        if (parent)
                g_free (parent);
}

static void
cache_del_parent (const char* path)
{
        char* parent = NULL;
        struct node* pnode = NULL;
        const char* name;
        const char* s = strrchr (path, '/');
        if (s) {
                if (s == path) {
                        parent = g_strdup ("/");
                        pnode = cache_lookup (parent);
                } else {
                        parent = g_strndup (path, s - path);
                        pnode = cache_lookup (parent);
                }
        }
        name = s + 1;

        if (pnode == NULL) {
                cache_node_changed (path);
                if (parent)
                        g_free (parent);
                return;
        }

#ifdef NEVER
        gf_log ("fuse-cache", GF_LOG_INFO,
                "rrrrr cache_del_parent() (%s,%s)",
                parent, name);
#endif /* NEVER */

        cache_del_path (parent, name);

        if (parent)
                g_free (parent);
}

void
cache_invalidate (const char* path, invalidate_parent_t touch_parent)
{
        if (!cache.on)
                return;

        uv_mutex_lock (&cache.lock);
        if (touch_parent == IP_NODO)
                cache_purge (path);
        else if (touch_parent == IP_TOUCH)
                cache_touch_parent (path);
        else if (touch_parent == IP_RELOAD) {
                cache_purge (path);
                cache_dirty_parent (path);
        }
        else if (touch_parent == IP_ADD) {
                cache_purge (path);
                cache_add_parent (path);
        }
        else if (touch_parent == IP_DELETE) {
                cache_purge (path);
                cache_del_parent (path);
        }
        uv_mutex_unlock (&cache.lock);
}

static void
cache_invalidate_parent (const char* path)
{
        if (!cache.on)
                return;

        uv_mutex_lock (&cache.lock);
        cache_dirty_parent (path);
        uv_mutex_unlock (&cache.lock);
}

void
cache_invalidate_write (const char* path)
{
        uv_mutex_lock (&cache.lock);
        /* save the stat when writing.
        cache_purge(path);
        */
        cache.write_ctr++;
        uv_mutex_unlock (&cache.lock);
}

static int
cache_del_children (const char* key, void* val_, const char* path)
{
        (void)val_;
        if (strncmp (key, path, strlen (path)) == 0)
                return TRUE;
        else
                return FALSE;
}

static void
cache_do_rename (const char* from, const char* to)
{
        uv_mutex_lock (&cache.lock);
        g_hash_table_foreach_remove (cache.table, (GHRFunc)cache_del_children,
                                     (char*)from);
        cache_invalidate (from, IP_RELOAD);
        cache_invalidate (to, IP_RELOAD);
        uv_mutex_unlock (&cache.lock);
}

static struct node*
cache_get (const char* path)
{
        struct node* node = cache_lookup (path);
        if (node == NULL) {
                char* pathcopy = g_strdup (path);
                node = g_new0 (struct node, 1);
                g_hash_table_insert (cache.table, pathcopy, node);
        }
        return node;
}

void
cache_add_attr (const char* path, const struct fuse_stat* stbuf, uint64_t wrctr)
{
        struct node* node;

        if (!cache.on)
                return;

        uv_mutex_lock (&cache.lock);
        if (wrctr == cache.write_ctr) {
                node = cache_get (path);
                node->nullpath = 0;
                node->stat = *stbuf;
                time_t stat_valid = time (NULL) + cache.stat_timeout_secs;
                if (stat_valid > node->valid)
                        node->valid = stat_valid;
                cache_clean ();
        }
        uv_mutex_unlock (&cache.lock);
}

static void
cache_add_dir (const char* path, GList* dir)
{
        struct node* node;

        uv_mutex_lock (&cache.lock);
        node = cache_get (path);
        free_dir (node->dir);
        node->dir = dir;
        node->dir_valid = time (NULL) + cache.dir_timeout_secs;
        if (node->dir_valid > node->valid)
                node->valid = node->dir_valid;
        cache_clean ();
        uv_mutex_unlock (&cache.lock);
}

static gint
compare_filename (gconstpointer a,
                  gconstpointer b)
{
        return strcmp (a, b);
}

static void
cache_add_path (const char* path, const char* name)
{
        struct node* node;

        node = cache_get (path);
        if (node->dir) { /* only append the node was fetched by getdir() */
                node->dir = g_list_prepend (node->dir, g_strdup (name));
                node->dir_valid = time (NULL) + cache.dir_timeout_secs;
                if (node->dir_valid > node->valid)
                        node->valid = node->dir_valid;
        }
        cache_clean ();
}

static void
cache_del_path (const char* path, const char* name)
{
        GList * filename_node;
        struct node* node;

        node = cache_get (path);

        filename_node = g_list_find_custom (node->dir, name, compare_filename);
        if (filename_node) {
                g_free (filename_node->data);
                node->dir = g_list_delete_link  (node->dir, filename_node);
        }
        node->dir_valid = time (NULL) + cache.dir_timeout_secs;
        if (node->dir_valid > node->valid)
                node->valid = node->dir_valid;
        cache_clean ();
}

static size_t
my_strnlen (const char* s, size_t maxsize)
{
        const char* p;
        for (p = s; maxsize && *p; maxsize--, p++)
                ;
        return p - s;
}

static void
cache_add_link (const char* path, const char* link, size_t size)
{
        struct node* node;

        uv_mutex_lock (&cache.lock);
        node = cache_get (path);
        g_free (node->link);
        node->link = g_strndup (link, my_strnlen (link, size - 1));
        node->link_valid = time (NULL) + cache.link_timeout_secs;
        if (node->link_valid > node->valid)
                node->valid = node->link_valid;
        cache_clean ();
        uv_mutex_unlock (&cache.lock);
}

static void
cache_add_nullpath (const char* path)
{
        struct node* node;

        uv_mutex_lock (&cache.lock);
        node = cache_get (path);
        free_dir (node->dir);
        node->dir = NULL;
        node->nullpath = 1;
        time_t stat_valid = time (NULL) + cache.empty_timeout_secs;
        if (stat_valid > node->valid)
                node->valid = stat_valid;
        uv_mutex_unlock (&cache.lock);
}

static int
cache_get_attr (const char* path, struct fuse_stat* stbuf)
{
        struct node* node;
        int err = -EAGAIN;
        uv_mutex_lock (&cache.lock);
        node = cache_lookup (path);
        if (node != NULL) {
                time_t now = time (NULL);
                if (node->valid - now >= 0) {
                        if (!node->nullpath) {
                                *stbuf = node->stat;
                                err = 0;
                        } else {
                                err = -ENOENT;
                        }
                }
        }
        uv_mutex_unlock (&cache.lock);
        return err;
}

uint64_t
cache_get_write_ctr (void)
{
        uint64_t res;

        uv_mutex_lock (&cache.lock);
        res = cache.write_ctr;
        uv_mutex_unlock (&cache.lock);

        return res;
}

static int
cache_getattr (const char* path, struct fuse_stat* stbuf)
{
        int err = cache_get_attr (path, stbuf);
        if (err == -ENOENT)
                goto end;

        if (!err && stbuf->st_size != 0) // BUGBUG: gluster bug
                goto end;

        uint64_t wrctr = cache_get_write_ctr ();
        err = cache.next_oper->oper.getattr (path, stbuf);
        if (err == -ENOENT) {
                cache_invalidate (path, IP_DELETE);
        }
        else if (!err)
                cache_add_attr (path, stbuf, wrctr);

end:

#if 0
        gf_log ("fuse-cache", GF_LOG_INFO,
                "dddddddddd cache_getattr() (%d,%s),mode=%o,size=%d,uid|gid=%d|%d",
                err, path, stbuf->st_mode, stbuf->st_size,stbuf->st_uid,stbuf->st_gid);
#endif /* NEVER */

        return err;
}

static int
cache_readlink (const char* path, char* buf, size_t size)
{
        struct node* node;
        int err;

        uv_mutex_lock (&cache.lock);
        node = cache_lookup (path);
        if (node != NULL) {
                time_t now = time (NULL);
                if (node->link_valid - now >= 0) {
                        strncpy (buf, node->link, size - 1);
                        buf[size - 1] = '\0';
                        uv_mutex_unlock (&cache.lock);
                        return 0;
                }
        }
        uv_mutex_unlock (&cache.lock);
        err = cache.next_oper->oper.readlink (path, buf, size);
        if (!err)
                cache_add_link (path, buf, size);

        return err;
}

static int fc;

static int
cache_dirfill (fuse_cache_dirh_t ch, const char* name,
               const struct fuse_stat* stbuf)
{

#if 0
                gf_log ("fuse-cache", GF_LOG_INFO,
                        "vvvvv cache_dirfill(%d) (%s)", ++fc, name);
#endif /* NEVER */

        int err = ch->filler (ch->h, name, 0, 0);
        if (!err) {
                ch->dir = g_list_prepend (ch->dir, g_strdup (name));
                if (stbuf->st_mode & S_IFMT) {
                        char* fullpath;
                        const char* basepath = !ch->path[1] ? "" : ch->path;

                        fullpath = g_strdup_printf ("%s/%s", basepath, name);
                        cache_add_attr (fullpath, stbuf, ch->wrctr);
                        g_free (fullpath);
                }
        }
        return err;
}

int
cache_getdir (const char* path, fuse_dirh_t h, fuse_dirfil_t filler)
{
        struct fuse_cache_dirhandle ch;
        int err = 0;
        GList* dir;
        struct node* node;
        int dir_count = 0;

#if 0
                        gf_log ("fuse-cache", GF_LOG_INFO,
                                "uuuuu cache_getdir() (%s)", path);
#endif /* NEVER */

        uv_mutex_lock (&cache.lock);
        node = cache_lookup (path);
        if (node != NULL && node->dir != NULL) {
                time_t now = time (NULL);
                if (node->dir_valid == 0)
                        goto unlock;
                else if (node->dir_valid - now < 0)
                        cache_node_changed (path);

                const char* basepath = !path[1] ? "" : path;

                dir = node->dir;
                while (dir != NULL) {
                        struct node* subnode;
                        char* fullpath;
                        fullpath = g_strdup_printf ("%s/%s", basepath,
                                                    (char*)dir->data);
#ifdef NEVER
                        subnode = cache_lookup (fullpath);
                        if (subnode && !subnode->nullpath) {
                                //if (strcmp(basepath, ".") != 0 &&
                                //    strcmp(basepath, "..") != 0) {
                                //        dir_count++;
                                        filler (h, (char*)dir->data, 0, 0);
                                //}
                        }
#endif /* NEVER */

                        filler (h, (char*)dir->data, 0, 0);

#if 0
                        gf_log ("fuse-cache", GF_LOG_INFO,
                                "aaaaaa cache_getdir() (%s)", fullpath);
#endif /* NEVER */
                        g_free (fullpath);

                        dir = dir->next;
                }

                //if (dir_count > 0) {
                //        filler (h, ".", 0, 0);
                //        filler (h, "..", 0, 0);
                        uv_mutex_unlock (&cache.lock);
                        return 0;
                //}
        }
unlock:
        uv_mutex_unlock (&cache.lock);

        fc = 0;

        ch.path = path;
        ch.h = h;
        ch.filler = filler;
        ch.dir = NULL;
        ch.wrctr = cache_get_write_ctr ();
        err = cache.next_oper->cache_getdir (path, &ch, cache_dirfill);
        if (!err)
                cache_add_dir (path, ch.dir);
        else
                free_dir (ch.dir);
        return err;
}

static int
cache_unity_dirfill (fuse_cache_dirh_t ch, const char* name,
                     const struct fuse_stat* stbuf)
{
        (void)stbuf;
        return ch->filler (ch->h, name, 0, 0);
}

static int
cache_unity_getdir (const char* path, fuse_dirh_t h, fuse_dirfil_t filler)
{
        struct fuse_cache_dirhandle ch;
        ch.h = h;
        ch.filler = filler;
        return cache.next_oper->cache_getdir (path, &ch, cache_unity_dirfill);
}

static int
cache_mknod (const char* path, mode_t mode, dev_t rdev)
{
        int err = cache.next_oper->oper.mknod (path, mode, rdev);
        if (!err)
                cache_invalidate (path, IP_RELOAD);
        return err;
}

static int
cache_mkdir (const char* path, mode_t mode)
{
        int err = cache.next_oper->oper.mkdir (path, mode);
        if (err == 0 || err == -EEXIST) {
                cache_invalidate (path, IP_ADD);
        }
        return err;
}

static int
cache_unlink (const char* path)
{
        int err = cache.next_oper->oper.unlink (path);
#ifdef NEVER
        if (err == 0 || err == -ENOENT) {
                cache_add_nullpath (path);
        }
#endif /* NEVER */
        if (!err)
                cache_invalidate (path, IP_DELETE);
        return err;
}

static int
cache_rmdir (const char* path)
{
        int err = cache.next_oper->oper.rmdir (path);
#ifdef NEVER
        if (err == 0 || err == -ENOENT) {
                cache_add_nullpath (path);
        }
#endif /* NEVER */
        if (!err)
                cache_invalidate (path, IP_DELETE);
        return err;
}

static int
cache_symlink (const char* from, const char* to)
{
        int err = cache.next_oper->oper.symlink (from, to);
        if (!err)
                cache_invalidate (to, IP_RELOAD);
        return err;
}

static int
cache_rename (const char* from, const char* to)
{
        int err = cache.next_oper->oper.rename (from, to);
        if (!err)
                cache_do_rename (from, to);
        return err;
}

static int
cache_link (const char* from, const char* to)
{
        int err = cache.next_oper->oper.link (from, to);
        if (!err) {
                cache_invalidate (from, IP_RELOAD);
                cache_invalidate (to, IP_RELOAD);
        }
        return err;
}

static int
cache_chmod (const char* path, mode_t mode)
{
        int err = cache.next_oper->oper.chmod (path, mode);
        if (!err)
                cache_invalidate (path, IP_TOUCH);
        return err;
}

static int
cache_chown (const char* path, uid_t uid, gid_t gid)
{
        int err = cache.next_oper->oper.chown (path, uid, gid);
        if (!err)
                cache_invalidate (path, IP_TOUCH);
        return err;
}

static int
cache_truncate (const char* path, off_t size)
{
        int err = cache.next_oper->oper.truncate (path, size);
        if (!err)
                cache_invalidate (path, IP_TOUCH);
        return err;
}

static int
cache_utime (const char* path, struct utimbuf* buf)
{
        int err = cache.next_oper->oper.utime (path, buf);
#if 0
        if (!err)
                cache_invalidate (path, 0);
#endif /* NEVER */
        return err;
}

static int
cache_write (const char* path, const char* buf, size_t size, off_t offset,
             struct fuse_file_info* fi)
{
        int res = cache.next_oper->oper.write (path, buf, size, offset, fi);
        if (res >= 0)
                cache_invalidate_write (path);
        return res;
}

static int
cache_flush (const char* path, struct fuse_file_info* fi)
{
        int res = cache.next_oper->oper.flush (path, fi);
        if (res >= 0)
                cache_invalidate (path, IP_NODO);
        return res;
}

static int
cache_release (const char* path, struct fuse_file_info* fi)
{
        int err = cache.next_oper->oper.release (path, fi);
#if 0
        if (!err)
                cache_invalidate (path, 0);
#endif /* NEVER */
        return err;
}

static int
cache_statfs (const char *path, struct fuse_statvfs *stbuf)
{
        int err = cache.next_oper->oper.statfs (path, stbuf);
        return err;
}

#if FUSE_VERSION >= 25
static int
cache_create (const char* path, mode_t mode, struct fuse_file_info* fi)
{
        int err = cache.next_oper->oper.create (path, mode, fi);
        if (!err)
                cache_invalidate (path, IP_ADD);
        return err;
}

static int
cache_ftruncate (const char* path, off_t size, struct fuse_file_info* fi)
{
        int err = cache.next_oper->oper.ftruncate (path, size, fi);
        if (!err)
                cache_invalidate (path, IP_TOUCH);
        return err;
}

static int
cache_fgetattr (const char* path, struct fuse_stat* stbuf, struct fuse_file_info* fi)
{
        int err = cache_get_attr (path, stbuf);
        if (err) {
                uint64_t wrctr = cache_get_write_ctr ();
                err = cache.next_oper->oper.fgetattr (path, stbuf, fi);
                if (!err)
                        cache_add_attr (path, stbuf, wrctr);
        }
        return err;
}
#endif

static int
fill_cache_getdir (const char* path, fuse_dirh_t h, fuse_dirfil_t filler)
{
        struct fuse_cache_dirhandle ch;
        int err;

        ch.path = path;
        ch.h = h;
        ch.filler = filler;
        ch.dir = NULL;
        ch.wrctr = cache_get_write_ctr ();
        err = cache.next_oper->cache_getdir (path, &ch, cache_dirfill);
        if (!err)
                cache_add_dir (path, ch.dir);
        else
                free_dir (ch.dir);
        return err;
}

static void
cache_node_changed (const char* path)
{
        struct cache_refresh_node *entry;
        int append = 1;

        uv_mutex_lock (&cache_refresh_lock);
        list_for_each_entry (entry, &cache_refresh_list, list) {
                if (strcmp (entry->path, path) == 0) {
                        append = 0;
                        break;
                }
        }
        uv_mutex_unlock (&cache_refresh_lock);

        if (append) {
                struct cache_refresh_node* r =
                        SH_CALLOC (1, sizeof (struct cache_refresh_node), 0);
                if (r == NULL)
                        return;

                r->path = g_strdup(path);
                r->type = RT_dir;

                uv_mutex_lock (&cache_refresh_lock);
                list_add (&r->list, &cache_refresh_list);
                uv_cond_signal (&cache_refresh_cond);
                uv_mutex_unlock (&cache_refresh_lock);
        }
}

static int
dummy_fuse_dirfil (fuse_dirh_t h, const char *name,
                   int type, fuse_ino_t ino)
{
        return 0;
}

static void *
cache_update_proc (void *data)
{

        struct cache_refresh_node* r = NULL;

        for (;;) {
                uv_mutex_lock (&cache_refresh_lock);

                while (list_empty (&cache_refresh_list)) {
                        uv_cond_wait (&cache_refresh_cond,
                                      &cache_refresh_lock);
                }

                list_for_each_entry (r, &cache_refresh_list, list) {
                        break;
                }

                uv_mutex_unlock (&cache_refresh_lock);

                switch (r->type) {
                case RT_attr:
                        break;

                case RT_dir:
                        fill_cache_getdir (r->path, NULL, dummy_fuse_dirfil);
                        break;
                }

                uv_mutex_lock (&cache_refresh_lock);
                list_del (&r->list);
                uv_mutex_unlock (&cache_refresh_lock);

                g_free (r->path);
                SH_FREE (r);
        }

        return NULL;
}

static void
cache_unity_fill (struct fuse_cache_operations* oper,
                  struct fuse_operations* cache_oper)
{
#if FUSE_VERSION >= 23
        cache_oper->init = oper->oper.init;
#endif
        cache_oper->getattr = oper->oper.getattr;
        cache_oper->access = oper->oper.access;
        cache_oper->readlink = oper->oper.readlink;
        cache_oper->getdir = cache_unity_getdir;
        cache_oper->mknod = oper->oper.mknod;
        cache_oper->mkdir = oper->oper.mkdir;
        cache_oper->symlink = oper->oper.symlink;
        cache_oper->unlink = oper->oper.unlink;
        cache_oper->rmdir = oper->oper.rmdir;
        cache_oper->rename = oper->oper.rename;
        cache_oper->link = oper->oper.link;
        cache_oper->chmod = oper->oper.chmod;
        cache_oper->chown = oper->oper.chown;
        cache_oper->truncate = oper->oper.truncate;
        cache_oper->utime = oper->oper.utime;
        cache_oper->open = oper->oper.open;
        // cache_oper->readdir     = oper->oper.readdir,
        cache_oper->read = oper->oper.read;
        cache_oper->write = oper->oper.write;
        cache_oper->flush = oper->oper.flush;
        cache_oper->release = oper->oper.release;
        cache_oper->fsync = oper->oper.fsync;
        cache_oper->statfs = oper->oper.statfs;
        cache_oper->setxattr = oper->oper.setxattr;
        cache_oper->getxattr = oper->oper.getxattr;
        cache_oper->listxattr = oper->oper.listxattr;
        cache_oper->removexattr = oper->oper.removexattr;
#if FUSE_VERSION >= 25
        cache_oper->create = oper->oper.create;
        cache_oper->ftruncate = oper->oper.ftruncate;
        cache_oper->fgetattr = oper->oper.fgetattr;
#endif
#if FUSE_VERSION >= 29
        cache_oper->flag_nullpath_ok = oper->oper.flag_nullpath_ok;
        cache_oper->flag_nopath = oper->oper.flag_nopath;
#endif
}

static void
cache_fill (struct fuse_cache_operations* oper,
            struct fuse_operations* cache_oper)
{
        cache_oper->getattr = oper->oper.getattr ? cache_getattr : NULL;
        cache_oper->readlink = oper->oper.readlink ? cache_readlink : NULL;
        cache_oper->getdir = oper->cache_getdir ? cache_getdir : NULL;
        cache_oper->mknod = oper->oper.mknod ? cache_mknod : NULL;
        cache_oper->mkdir = oper->oper.mkdir ? cache_mkdir : NULL;
        cache_oper->symlink = oper->oper.symlink ? cache_symlink : NULL;
        cache_oper->unlink = oper->oper.unlink ? cache_unlink : NULL;
        cache_oper->rmdir = oper->oper.rmdir ? cache_rmdir : NULL;
        cache_oper->rename = oper->oper.rename ? cache_rename : NULL;
        cache_oper->link = oper->oper.link ? cache_link : NULL;
        cache_oper->chmod = oper->oper.chmod ? cache_chmod : NULL;
        cache_oper->chown = oper->oper.chown ? cache_chown : NULL;
        cache_oper->truncate = oper->oper.truncate ? cache_truncate : NULL;
        // cache_oper->readdir  = oper->oper.readdir ? cache_readdir : NULL;
        cache_oper->utime = oper->oper.utime ? cache_utime : NULL;
        cache_oper->write = oper->oper.write ? cache_write : NULL;
        cache_oper->release = oper->oper.release ? cache_release : NULL;
        cache_oper->statfs = oper->oper.statfs ? cache_statfs : NULL;
#if FUSE_VERSION >= 25
        cache_oper->create = oper->oper.create ? cache_create : NULL;
        cache_oper->ftruncate = oper->oper.ftruncate ? cache_ftruncate : NULL;
        cache_oper->fgetattr = oper->oper.fgetattr ? cache_fgetattr : NULL;
#endif
#if FUSE_VERSION >= 29
        cache_oper->flag_nullpath_ok = 0;
        cache_oper->flag_nopath = 0;
#endif
}

struct fuse_operations*
cache_init (struct fuse_cache_operations* oper)
{
        static struct fuse_operations cache_oper;
        pthread_t thread;
        int ret = -1;

        cache.next_oper = oper;

        cache_unity_fill (oper, &cache_oper);
        if (cache.on) {
                cache_fill (oper, &cache_oper);
                uv_mutex_init (&cache.lock);
                cache.table = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free, free_node);
                if (cache.table == NULL) {
                        fprintf (stderr, "failed to create cache\n");
                        return NULL;
                }


                INIT_LIST_HEAD (&cache_refresh_list);
                uv_mutex_init (&cache_refresh_lock);
                uv_cond_init (&cache_refresh_cond);

                ret = gf_thread_create (&thread, NULL,
                                        cache_update_proc, NULL);
                if (ret != 0) {
                        gf_log ("fuse-cache", GF_LOG_DEBUG,
                                "pthread_create() failed (%s)",
                                strerror (errno));
                }
        }
        return &cache_oper;
}

static const struct fuse_opt cache_opts[] =
  { { "cache=yes", offsetof (struct cache, on), 1 },
    { "cache=no", offsetof (struct cache, on), 0 },
    { "cache_timeout=%u", offsetof (struct cache, stat_timeout_secs), 0 },
    { "cache_timeout=%u", offsetof (struct cache, dir_timeout_secs), 0 },
    { "cache_timeout=%u", offsetof (struct cache, link_timeout_secs), 0 },
    { "cache_stat_timeout=%u", offsetof (struct cache, stat_timeout_secs), 0 },
    { "cache_dir_timeout=%u", offsetof (struct cache, dir_timeout_secs), 0 },
    { "cache_link_timeout=%u", offsetof (struct cache, link_timeout_secs), 0 },
    { "cache_max_size=%u", offsetof (struct cache, max_size), 0 },
    { "cache_clean_interval=%u", offsetof (struct cache, clean_interval_secs),
      0 },
    { "cache_min_clean_interval=%u",
      offsetof (struct cache, min_clean_interval_secs), 0 },
    FUSE_OPT_END };

int
cache_parse_options (struct fuse_args* args)
{
        cache.empty_timeout_secs = DEFAULT_CACHE_EMPTY_TIMEOUT_SECS;
        cache.stat_timeout_secs = DEFAULT_CACHE_STAT_TIMEOUT_SECS;
        cache.dir_timeout_secs = DEFAULT_CACHE_DIR_TIMEOUT_SECS;
        cache.link_timeout_secs = DEFAULT_CACHE_LINK_TIMEOUT_SECS;
        cache.max_size = DEFAULT_MAX_CACHE_SIZE;
        cache.clean_interval_secs = DEFAULT_CACHE_CLEAN_INTERVAL_SECS;
        cache.min_clean_interval_secs = DEFAULT_MIN_CACHE_CLEAN_INTERVAL_SECS;
        cache.on = 1;

        return fuse_opt_parse (args, &cache, cache_opts, NULL);
}
