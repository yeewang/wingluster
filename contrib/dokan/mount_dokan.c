
#include "fuse.h"
#include "mount_util.h"
#include "mount-gluster-compat.h"

#ifdef GF_FUSERMOUNT
#define FUSERMOUNT_PROG FUSERMOUNT_DIR "/fusermount-glusterfs"
#else
#define FUSERMOUNT_PROG "fusermount"
#endif
#define FUSE_DEVFD_ENV "_FUSE_DEVFD"

#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#endif /* __FreeBSD__ */

/* FUSE: function is called fuse_kern_unmount() */
void
gf_fuse_unmount (const char *mountpoint, int fd)
{
        int res;
        int pid;

        if (!mountpoint)
                return;

        if (fd != -1) {
                struct pollfd pfd;

                pfd.fd = fd;
                pfd.events = 0;
                res = poll (&pfd, 1, 0);
                /* If file poll returns POLLERR on the device file descriptor,
                   then the filesystem is already unmounted */
                if (res == 1 && (pfd.revents & POLLERR))
                        return;

                /* Need to close file descriptor, otherwise synchronous umount
                   would recurse into filesystem, and deadlock */
                close (fd);
        }

        if (geteuid () == 0) {
                fuse_mnt_umount ("fuse", mountpoint, mountpoint, 1);
                return;
        }

        res = umount2 (mountpoint, 2);
        if (res == 0)
                return;

        pid = fork ();
        if (pid == -1)
                return;

        if (pid == 0) {
                const char *argv[] = { FUSERMOUNT_PROG, "-u", "-q", "-z",
                                       "--", mountpoint, NULL };

                execvp (FUSERMOUNT_PROG, (char **)argv);
                _exit (1);
        }
        waitpid (pid, NULL, 0);
}


/* gluster-specific routines */

static char *
escape (char *s)
{
        size_t len = 0;
        char *p = NULL;
        char *q = NULL;
        char *e = NULL;

        for (p = s; *p; p++) {
                if (*p == ',')
                       len++;
                len++;
        }

        e = CALLOC (1, len + 1);
        if (!e)
                return NULL;

        for (p = s, q = e; *p; p++, q++) {
                if (*p == ',') {
                        *q = '\\';
                        q++;
                }
                *q = *p;
        }

        return e;
}

static struct fuse_operations xmp_oper = {
#ifdef NEVER
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
#endif /* NEVER */
};


static int
fuse_mount_sys (const char *mountpoint, char *fsname,
                unsigned long mountflags, char *mnt_param, int fd)
{
        int ret = -1;
        unsigned mounted = 0;

        int argc = 6;
        char *argv[12];
        argv[0] = "dokan";
        argv[1] = "-o";
        argv[2] = "volname=gluster";
        argv[3] = "-o";
        argv[4] = "fsname=glusterfs";
        argv[5] = mountpoint;
        argv[6] = NULL;

        umask(0);
        ret = fuse_main_real(argc, argv, &xmp_oper, sizeof(xmp_oper), NULL);

        if (ret != 0)
                goto out;
        else
                mounted = 1;

out:
        if (ret == -1) {
                GFFUSE_LOGERR("ret = -1\n");
                if (mounted)
                        umount2 (mountpoint, 2); /* lazy umount */
        }

        return ret;
}

int
gf_fuse_mount (const char *mountpoint, char *fsname,
               unsigned long mountflags, char *mnt_param,
               pid_t *mnt_pid, int status_fd)
{
        int   fd  = -1;
        pid_t pid = -1;
        int   ret = -1;

        /* start mount agent */
        pid = fork();
        switch (pid) {
        case 0:
                /* hello it's mount agent */
                if (!mnt_pid) {
                        /* daemonize mount agent, caller is
                         * not interested in waiting for it
                         */
                        pid = fork ();
                        if (pid)
                                exit (pid == -1 ? 1 : 0);
                }


                /* start mount agent */
                ret = fuse_mount_sys (mountpoint, fsname, mountflags, mnt_param,
                      fd);
                if (ret == -1)
                        GFFUSE_LOGERR ("mount of %s to %s (%s) failed",
                                       fsname, mountpoint, mnt_param);

                if (status_fd >= 0)
                        (void)write (status_fd, &ret, sizeof (ret));

                exit (!!ret);
                /* bye mount agent */
        case -1:
                close (fd);
                fd = -1;
        }

        if (mnt_pid)
               *mnt_pid = pid;

        /* Windows always returns 0. */
        return 0;
}

