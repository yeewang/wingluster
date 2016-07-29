
#include <sys/cygwin.h>
#include "fuse.h"
#include "mount_util.h"
#include "mount-gluster-compat.h"

#ifdef GF_FUSERMOUNT
#define FUSERMOUNT_PROG FUSERMOUNT_DIR "/fusermount-glusterfs"
#else
#define FUSERMOUNT_PROG "fusermount"
#endif


/* Conversion from cygwin path to windows path */
static const char *
create_winpath_from_cygpath(const char *cygpath)
{
        const char *winpath;
        winpath = (const char *)cygwin_create_path (
                CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, cygpath);
        return winpath;
}

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

extern struct fuse_operations dokan_operations;

static int
fuse_mount_sys (const char *mountpoint, char *fsname,
                unsigned long mountflags, char *mnt_param)
{
        int ret = -1;
        unsigned mounted = 0;

        int argc = 7;
        char *argv[12];
        argv[0] = "dokan";
        argv[1] = "-o";
        argv[2] = "volname=gluster";
        argv[3] = "-o";
        argv[4] = "fsname=glusterfs";
        argv[5] = "-d";
        argv[6] = mountpoint;
        argv[7] = NULL;

        umask(0);
        ret = fuse_main_real(argc, argv, &dokan_operations, sizeof(dokan_operations), NULL);

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
               int status_fd)
{
        pid_t pid = -1;
        int   ret = -1;
        const char *winpath = NULL;

        /* convert cygwin path to Windows */
        winpath = create_winpath_from_cygpath (mountpoint);
        if (winpath == NULL)
                GFFUSE_LOGERR ("Convert linux path(%s) to windows failed",
                        mountpoint);

        /* start mount agent */
        ret = fuse_mount_sys (winpath, fsname, mountflags, mnt_param);
        if (ret != 0)
                GFFUSE_LOGERR ("mount of %s to %s (%s) failed",
                               fsname, mountpoint, mnt_param);

        free (winpath);
        gf_log ("glusterfs-fuse", GF_LOG_INFO, "mount agent exited.",
               fsname, mountpoint, mnt_param);

        if (status_fd >= 0)
                (void)write (status_fd, &ret, sizeof (ret));

        return ret;
}

