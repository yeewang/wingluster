
#include <glib.h>
#include <sys/types.h>
#include <pwd.h>
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
char *
create_winpath_from_cygpath(const char *cygpath)
{
        char *winpath = NULL;

        winpath = (char *)cygwin_create_path (
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

static struct fuse_opt ext_opts[] = {
	FUSE_OPT_END
};

extern struct fuse_cache_operations winfsp_oper;

struct fuse *
gf_fuse_mount (const char *mountpoint, char *fsname,
               unsigned long mountflags, char *mnt_param,
               int status_fd)
{
        char idmap[64];
        struct passwd *passwd;
        struct fuse *fuse = NULL;
        char *winpath = NULL;
	int res;

        /* get uid/gid from local user name */
        passwd = getpwuid(getuid());
        if (0 != passwd)
                snprintf(idmap, sizeof idmap, "-ouid=%d,gid=%d", passwd->pw_uid, passwd->pw_gid);

        passwd = getpwnam("yiwang");
        if (0 != passwd)
                snprintf(idmap, sizeof idmap, "-ouid=%d,gid=%d", passwd->pw_uid, passwd->pw_gid);

        /* convert cygwin path to Windows */
        winpath = create_winpath_from_cygpath (mountpoint);
        if (winpath == NULL) {
                GFFUSE_LOGERR ("Convert linux path(%s) to windows failed",
                        mountpoint);
                goto out;
        }
        winpath[2] = '\0';

        char param[255];
        char *volserver = NULL;
        char *volfile = NULL;
        char *p = strchr(fsname, ':');
        if (p)
                *p = '\0';
        volserver = fsname;
        volfile = ++p;
        while (*p != '\0') {
                if (*p == '/') {
                        strcpy(p, p+1);
                }
                p++;
        }
        snprintf(param, sizeof(param), "--VolumePrefix=\\%s\\%s", volserver, volfile);

        char *argv[] = {
                "mount",
                param,
                "--FileSystemName=STORSWIFT-FS",
                winpath,
                NULL };
	struct fuse_args args = FUSE_ARGS_INIT(4, argv);

	if (fuse_opt_parse(&args, NULL, ext_opts, NULL) == -1) {
                GFFUSE_LOGERR ("parse ext_opts failed");
		goto out;
        }

	res = cache_parse_options(&args);
	if (res == -1) {
                GFFUSE_LOGERR ("parse cache failed");
                goto out;
        }

	//fuse_opt_add_arg(&args, "-d");
        fuse_opt_add_arg(&args, "-f");
        fuse_opt_add_arg(&args, idmap);

	if (fuse_is_lib_option("ac_attr_timeout="))
		fuse_opt_add_arg(&args, "-oauto_cache,ac_attr_timeout=0");

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
		if (res == -1) {
                        GFFUSE_LOGERR ("parse cmdline failed");
			goto out;
                }

                foreground = 1;

                /*
		res = stat(mountpoint, &st);
		if (res == -1) {
			GFFUSE_LOGERR ("check mountpoint failed: %d", errno);
			goto out;
		}
		*/

		ch = fuse_mount(mountpoint, &args);
		if (!ch) {
                        GFFUSE_LOGERR ("mount failed: %d", errno);
			goto out;
                }

		fuse_operations = cache_init(&winfsp_oper);
		fuse = fuse_new(ch, &args, fuse_operations,
				sizeof(struct fuse_operations), NULL);
		if (fuse == NULL) {
                        GFFUSE_LOGERR ("fuse_new failed: %d", errno);
			fuse_unmount(mountpoint, ch);
			goto out;
		}

		res = fuse_daemonize(foreground);
		if (res != -1)
			res = fuse_set_signal_handlers(fuse_get_session(fuse));

		if (res == -1) {
                        GFFUSE_LOGERR ("fuse_daemonize failed: %d", errno);

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

                gf_log ("glusterfs-fuse", GF_LOG_INFO, "mount agent exited.");

                free(winpath);
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

