/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (c) 2010 Gluster, Inc. <http://www.gluster.com>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#ifndef GF_CYGWIN_HOST_OS
void gf_fuse_unmount (const char *mountpoint, int fd);
int gf_fuse_unmount_daemon (const char *mountpoint, int fd);
int gf_fuse_mount (const char *mountpoint, char *fsname, char *mnt_param,
                   pid_t *mtab_pid, int status_fd);
#else

void gf_fuse_unmount (const char *mountpoint, struct fuse *fuse);

struct fuse * gf_fuse_mount (const char *mountpoint, char *fsname,
              unsigned long mountflags, char *mnt_param,
              int status_fd);

#endif /* GF_CYGWIN_HOST_OS */

