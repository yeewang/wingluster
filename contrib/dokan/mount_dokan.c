
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
const char *
create_winpath_from_cygpath(const char *cygpath)
{
        const char *winpath = NULL;

        winpath = (const char *)cygwin_create_path (
                        CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, cygpath);
        return winpath;
}

void
gf_fuse_unmount (const char *mountpoint, struct fuse *fuse)
{
        if (fuse && mountpoint)
                fuse_teardown(fuse, mountpoint);
}

extern struct fuse_operations dokan_operations;

static struct fuse *
fuse_mount_sys (const char *mountpoint, char *fsname,
                unsigned long mountflags, char *mnt_param)
{
        int res = -1;
        struct fuse *fuse;
        char *mnt_point;
        int multithreaded;
        int argc = 8;
        char *argv[12];
        char *volname;

        if (asprintf(&volname, "volname=%s", fsname) == -1)
                return NULL;

        argv[0] = "dokan";
        argv[1] = "-o";
        argv[2] = volname;
        argv[3] = "-o";
        argv[4] = "fsname=StorSwift FS";
        argv[5] = "-n";
        argv[6] = "-f";
        argv[7] = mountpoint;
        argv[8] = NULL;

        umask(0);

        fuse = fuse_setup(argc, argv, &dokan_operations,
                          sizeof(dokan_operations), &mnt_point, &multithreaded,
                          NULL);
        if (fuse == NULL) {
                GFFUSE_LOGERR("ret = 1\n");
                free(volname);
                return NULL;
        }

        // MT loops are only supported on MSVC
        if (multithreaded)
                res = fuse_loop_mt(fuse);
        else
                res = fuse_loop(fuse);

        fuse_teardown(fuse, mountpoint);

        if (res < 0) {
                GFFUSE_LOGERR("ret = %d\n", res);
                free(volname);
                return NULL;
        }

        free(volname);

        return fuse;
}

struct fuse *
gf_fuse_mount (const char *mountpoint, char *fsname,
               unsigned long mountflags, char *mnt_param,
               int status_fd)
{
        int   ret = -1;
        const char *winpath = NULL;
        struct fuse *fuse = NULL;

        /* convert cygwin path to Windows */
        winpath = create_winpath_from_cygpath (mountpoint);
        if (winpath == NULL) {
                GFFUSE_LOGERR ("Convert linux path(%s) to windows failed",
                        mountpoint);
                goto out;
        }

        /* start mount agent */
        fuse = fuse_mount_sys (winpath, fsname, mountflags, mnt_param);
        if (fuse == NULL)
                GFFUSE_LOGERR ("mount of %s to %s (%s) failed",
                               fsname, mountpoint, mnt_param);

        free (winpath);
        gf_log ("glusterfs-fuse", GF_LOG_INFO, "mount agent exited.");

out:
        if (status_fd >= 0)
                (void)write (status_fd, &ret, sizeof (ret));

        return fuse;
}

