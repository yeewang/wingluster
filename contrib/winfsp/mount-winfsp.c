
#include <glib.h>
#include <sys/cygwin.h>
#include "fuse.h"
#include "mount_util.h"
#include "mount-gluster-compat.h"
#include "fuse-cache.h"


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
        if (fuse && mountpoint) {
                //fuse_unmount(mountpoint, fuse->ch);
        }
}

#if 0
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
        argv[6] = "-d";
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
gf_fuse_mount1 (const char *mountpoint, char *fsname,
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
#endif

static struct fuse_opt sshfs_opts[] = {
	FUSE_OPT_END
};

extern struct fuse_cache_operations winfsp_oper;

struct fuse *
gf_fuse_mount (const char *mountpoint, char *fsname,
               unsigned long mountflags, char *mnt_param,
               int status_fd)
{
        char *argv[] = { "mount", NULL };
        struct fuse *fuse = NULL;
	int res;
	struct fuse_args args = FUSE_ARGS_INIT(1, argv);
	char *tmp;
	const char *sftp_server;
	int libver;

	if (fuse_opt_parse(&args, NULL, sshfs_opts, NULL) == -1)
		goto out;

	res = cache_parse_options(&args);
	if (res == -1)
		goto out;

	if (fuse_is_lib_option("ac_attr_timeout="))
		fuse_opt_insert_arg(&args, 1, "-oauto_cache,ac_attr_timeout=0");

	tmp = g_strdup_printf("-osubtype=storswiftfs,fsname=%s", fsname);
	fuse_opt_insert_arg(&args, 1, tmp);
	g_free(tmp);

#if FUSE_VERSION >= 26
	{
		struct fuse_chan *ch;
		char *mountpoint;
		int multithreaded;
		int foreground;
		struct stat st;
                struct fuse_operations *fuse_operations;

		res = fuse_parse_cmdline(&args, &mountpoint, &multithreaded,
					 &foreground);
		if (res == -1)
			goto out;

		res = stat(mountpoint, &st);
		if (res == -1) {
			perror(mountpoint);
			goto out;
		}

		ch = fuse_mount("M:", &args);
		if (!ch)
			goto out;

		fuse_operations = cache_init(&winfsp_oper);
		fuse = fuse_new(ch, &args, fuse_operations,
				sizeof(struct fuse_operations), NULL);
		if (fuse == NULL) {
			fuse_unmount(mountpoint, ch);
			goto out;
		}

		res = fuse_daemonize(foreground);
		if (res != -1)
			res = fuse_set_signal_handlers(fuse_get_session(fuse));

		if (res == -1) {
			fuse_unmount(mountpoint, ch);
			fuse_destroy(fuse);
			goto out;
		}

		if (multithreaded)
			res = fuse_loop_mt(fuse);
		else
			res = fuse_loop(fuse);

		if (res == -1)
			res = 1;
		else
			res = 0;

		fuse_remove_signal_handlers(fuse_get_session(fuse));
		fuse_unmount(mountpoint, ch);
		fuse_destroy(fuse);
		free(mountpoint);
	}
#endif

	fuse_opt_free_args(&args);

out:
        if (status_fd >= 0)
                (void)write (status_fd, &res, sizeof (res));

        return fuse;
}

