/*
 * copyfs - copy on write filesystem  http://n0x.org/copyfs/
 * Copyright (C) 2004 Nicolas Vigier <boklm@mars-attacks.org>
 *                    Thomas Joubert <widan@net-42.eu.org>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
*/

#ifndef CREATE_H
# define CREATE_H

#define COPY_YES 1
#define COPY_NO 0
#define SUBVERSION_YES 1
#define SUBVERSION_NO 0

int create_new_version(const char *vpath);
int create_new_subversion(const char *vpath, mode_t mode, uid_t uid, gid_t gid);
int create_new_file(const char *vpath, mode_t mode, uid_t uid, gid_t gid, dev_t dev);
int create_new_symlink(const char *dest, const char *vpath, uid_t uid, gid_t gid);
int create_new_directory(const char *vpath, mode_t mode, uid_t uid, gid_t gid);
int create_copy_file(const char *source, const char *target);
int create_new_version_generic(const char *vpath, int subversion,
				      int do_copy, mode_t mode, uid_t uid,
				      gid_t gid);

#endif /* !CREATE_H */
