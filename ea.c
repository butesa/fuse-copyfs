/*
 * copyfs - copy on write filesystem  http://n0x.org/copyfs/
 * Copyright (C) 2004 Nicolas Vigier <boklm@mars-attacks.org>
 *                    Thomas Joubert <widan@net-42.eu.org>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fuse.h>
#include <unistd.h>
#include <dirent.h>

#include "helper.h"
#include "structs.h"
#include "write.h"
#include "rcs.h"
#include "ea.h"
#include "cache.h"

/*
 * We support extended attributes to allow user-space scripts to manipulate
 * the file system state, such as forcing a specific version to appear, ...
 *
 * The supported attributes are :
 *
 *  - rcs.locked_version : the current locked version for the file
 *  - rcs.metadata_dump  : a dump of the metadata, for scripts that need
 *                         to list the available versions.
 *  - rcs.purge			 : this is an ungettable attribute that purges
 * 						   copies of - or all of - a file.
 */

static void ea_prepare_data(const char *path_in, const char *name_in, char **path_out, char **name_out)
{
  char *pos;
  pos = strchr(name_in, ':');
  if (!pos) {
    *path_out = safe_strdup(path_in);
    *name_out = safe_strdup(name_in);
  }
  else {
    *name_out = safe_malloc(pos - name_in + 1);
    memcpy(*name_out, name_in, pos - name_in);
    (*name_out)[pos - name_in] = '\0';
    
    if (path_in[strlen(path_in)-1] == '/') {
      *path_out = safe_malloc(strlen(path_in) + strlen(pos + 1) + 1);
      strcpy(*path_out, path_in);
      strcpy(*path_out + strlen(path_in), pos + 1);
    }
    else {
      *path_out = safe_malloc(strlen(path_in) + strlen(pos + 1) + 2);
      strcpy(*path_out, path_in);
      (*path_out)[strlen(path_in)] = '/';
      strcpy(*path_out + strlen(path_in) + 1, pos + 1);
    }
  }
}

int ea_getxattr_rcs(const char *path, const char *name, char *value, size_t size)
{
  metadata_t *metadata;
  version_t *version;
  
  rcs_ignore_deleted = 1;
  metadata = rcs_translate_to_metadata(path, rcs_version_path);
  rcs_ignore_deleted = 0;
  if (!metadata)
    return -ENOENT;

  if (!strcmp(name, "rcs.purge"))
    {
      /* This one is write-only */
      return -EPERM;
    }
  else if (!strcmp(name, "rcs.locked_version"))
    {
      char buffer[64];
      int vid, svid;
      
      if (metadata->md_deleted)
      {
        strcpy(buffer, "0.0");
      }
      else
      {
        if (metadata->md_dfl_vid == -1)
          {
            vid = metadata->md_versions->v_vid;
            svid = metadata->md_versions->v_svid;
          }
        else
          {
            vid = metadata->md_dfl_vid;
            svid = metadata->md_dfl_svid;
          }
  
        /* Get the version number */
        snprintf(buffer, 64, "%i.%i", vid, svid);
      }

      /* Handle the EA protocol */
      if (size == 0)
        return strlen(buffer);
      if (strlen(buffer) > size)
        return -ERANGE;
      strcpy(value, buffer);
      return strlen(buffer);
    }
  else if (!strcmp(name, "rcs.metadata_dump"))
    {
      char **array, *result;
      unsigned int count;
      int res;

      /*
       * We need to pass the version metadata to userspace, but we also need
       * to pass the file type and modification type from the stat syscall,
       * since the userspace program may be running as a non-root, and thus
       * can't see the version store.
       */

      for (count = 0, version = metadata->md_versions; version;
        version = version->v_next)
        count++;
      array = safe_malloc(sizeof(char *) * (count + 1));
      memset(array, 0, sizeof(char *) * (count + 1));

      /* Traverse the version list and build the individual strings */
      for (count = 0, version = metadata->md_versions; version;
        version = version->v_next)
        {
          struct stat st_data;
      
          /* stat() the real file, but just ignore failures (bad version ?) */
          if (lstat(version->v_rfile, &st_data) < 0)
            {
              st_data.st_mode = S_IFREG;
              st_data.st_mtime = -1;
            }
          else
            st_data.st_mode &= ~07777;
      
          if (asprintf(&array[count], "%d:%d:%d:%d:%d:%lld:%ld",
            version->v_vid, version->v_svid,
            version->v_mode | st_data.st_mode, version->v_uid,
            version->v_gid, (long long)st_data.st_size, st_data.st_mtime) < 0)
            {
              unsigned int i;
      
              /* Free everything if it failed */
              for (i = 0; i < count; i++)
                free(array[i]);
              free(array);
              return -ENOMEM;
            }
      
          count++;
        }

      /* Build the final string */
      result = helper_build_composite("A", "|", array);
      helper_free_array(array);

      /* Handle the EA protocol */

      if (size == 0)
        res = strlen(result);
      else if (strlen(result) > size)
        res = -ERANGE;
      else
        {
          strcpy(value, result);
          res = strlen(result);
        }
      free(result);
      return res;
    }
  else if (!strcmp(name, "rcs.list_dir"))
    {
      struct dirent *entry;
      int res;
      DIR *dir;
      char *result;
      size_t result_size;
      string_list_t *file_list;
      string_list_t **file_list_ptr;
    
      file_list = NULL;
      file_list_ptr = &file_list;

      rcs_ignore_deleted = 1;
      version = rcs_find_version(metadata, LATEST, LATEST);
      rcs_ignore_deleted = 0;
      
      dir = opendir(version->v_rfile);
      if (!dir)
        {
          return -errno;
        }      
    
      /* Find the metadata files */
      while ((entry = readdir(dir)))
        {
          /*
           * We want the metadata files (because a versioned file is
           * behind them)
           */
          if (!strcmp(entry->d_name, METADATA_PREFIX))
            {
              /* This is the root's metadata, ignore it */
              continue;
            }
          else if (!strncmp(entry->d_name, METADATA_PREFIX,
                strlen(METADATA_PREFIX)))
            {
              char *file;
              metadata_t *file_metadata;
              int len;
      
              if (strcmp(path, "/"))
                file = helper_build_composite("SS", "/", path,
                  entry->d_name + strlen(METADATA_PREFIX));
              else
                file = helper_build_composite("-S", "/", entry->d_name +
                  strlen(METADATA_PREFIX));
              rcs_ignore_deleted = 1;
              file_metadata = rcs_translate_to_metadata(file, rcs_version_path);
              rcs_ignore_deleted = 0;
              free(file);
              if (!file_metadata)
                {
                  closedir(dir);
                  return -ENOENT;
                }
              
              *file_list_ptr = safe_malloc(sizeof(string_list_t));
              memset(*file_list_ptr, 0, sizeof(string_list_t));
              
              if (file_metadata->md_deleted)
                len = asprintf(&(*file_list_ptr)->sl_data, "0:0:0:0:0:0:0:%s",
                  entry->d_name + strlen(METADATA_PREFIX));
              else
                {
                  version_t *file_version;
                  struct stat st_data;
                  
                  file_version = rcs_find_version(file_metadata, LATEST, LATEST);
                  if (!file_version)
                    {
                      helper_free_string_list(file_list);
                      closedir(dir);
                      return -ENOENT;
                    }
                    
                  /* stat() the real file, but just ignore failures (bad version ?) */
                  if (lstat(file_version->v_rfile, &st_data) < 0)
                    {
                      st_data.st_mode = S_IFREG;
                      st_data.st_mtime = -1;
                    }
                  else
                    st_data.st_mode &= ~07777;
          
                  len = asprintf(&(*file_list_ptr)->sl_data, "%d:%d:%d:%d:%d:%lld:%ld:%s",
                    file_version->v_vid, file_version->v_svid,
                    file_version->v_mode | st_data.st_mode, file_version->v_uid,
                    file_version->v_gid, (long long)st_data.st_size, st_data.st_mtime,
                    entry->d_name + strlen(METADATA_PREFIX));
                }
              if (len < 0)
                {
                  /* Free everything if it failed */
                  helper_free_string_list(file_list);
                  closedir(dir);
                  return -ENOMEM;
                }
              
              file_list_ptr = &(*file_list_ptr)->sl_next;
            }
        }
    
      closedir(dir);

      /* Build the final string */
      result_size = helper_compose_string_list(&result, file_list, '\0');
      helper_free_string_list(file_list);

      /* Handle the EA protocol */

      if (size == 0)
        res = result_size;
      else if (result_size > size)
        res = -ERANGE;
      else
        {
          memcpy(value, result, result_size);
          res = result_size;
        }
      free(result);
      return res;
    }
  else
    {
      /* unknown rcs.*-attribute */
      return -EPERM;
    }
}

int ea_setxattr_rcs(const char *path, const char *name, const char *value, size_t size)
{
  metadata_t *metadata;
  version_t *version;
  
  rcs_ignore_deleted = 1;
  metadata = rcs_translate_to_metadata(path, rcs_version_path);
  rcs_ignore_deleted = 0;
  if (!metadata)
    return -ENOENT;

  if (!strcmp(name,"rcs.purge"))
    {
      /* Copy the value to NUL-terminate it */
      char *local;
      local = safe_malloc(size + 1);
      local[size] = '\0';
      memcpy(local, value, size);

      // Get the full path to the metadatafile
      char *mdfile=helper_build_meta_name(path, METADATA_PREFIX);
      if (!mdfile)
        return -ENOENT;
        
      int c=1; // how many versions to delete
      int vnum=1; // number of versions
      
      if(!strcmp(local,"A")) {
        // Delete them all
        // we don't have to count the versions
        // we just leave c and vnum at 1
      } else {
        // we have a number, so set c to it
        c=atoi(local);
        
        // Count the number of versions there are
        version = metadata->md_versions;
        while(version->v_next) { 
          version=version->v_next;
          vnum++; 
        }
      }
      
      /* Let's do this... Crawl through the list, nulling
       * next's and unlinking files
       */
      version_t *next;
      version = metadata->md_versions;
      if(c >= vnum) {
        // we're toasting them all...
        while(version) {
          //unlink file.. scary!
          unlink(version->v_rfile);
          /* No need to clean up version data.
           * This is done later by rcs_free_metadata */
          version=version->v_next;
        }
        
        // Free the metadata from cache
        cache_drop_metadata(metadata);
        rcs_free_metadata(metadata);
        
        // kill the metadata file too.. SCARY!!!
        unlink(mdfile);
      } else {
        // cull
        vnum-=c; // number of versions we want to _keep_.
        while(version) {
          if(vnum > 1) {
            // we want to keep this version
            vnum--;
            version=version->v_next;
        }
          else if (vnum == 1) {
          // this is the last version to keep
          vnum--;
          next=version->v_next;
            version->v_next = NULL;
          version=next;
        }
          else {
            //delete this version
            
          //unlink file.. scary!
          unlink(version->v_rfile);
          
            next=version->v_next;
          free(version->v_rfile);
          free(version);
            version=next;
          }
        }
        
        // We've made changes to the metadata, and got at least one
        // version left.. need to update it
        if (write_metadata_file(mdfile, metadata) == -1) {
          free(mdfile);
          return -errno;
        }
      }
      
      free(mdfile);
      return 0;
      
    }
  else if (!strcmp(name, "rcs.locked_version"))
    {
      struct fuse_context *context;
      unsigned int length;
      int vid, svid;
      char *dflfile, *metafile, *local;

      /* Copy the value to NUL-terminate it */
      local = safe_malloc(size + 1);
      local[size] = '\0';
      memcpy(local, value, size);

      vid = 0; svid = 0;
      if ((sscanf(local, "%d.%d%n", &vid, &svid, &length) != 2) ||
        (length != size))
        {
          free(local);
          return -EINVAL;
        }
      free(local);

      /* Check if we actually have that version (or a compatible version) */
      version = rcs_find_version(metadata, vid, svid);
      if (!version)
        return -EINVAL;

      /*
       * Only allow a user to change the version if the new version has the
       * same owner as the one requesting the change, or if the user is root,
       * to prevent curious users from resurrecting versions with too lax
       * permissions.
       */
      context = fuse_get_context();
      if ((context->uid != 0) && (context->uid != version->v_uid))
        return -EACCES;

      /* Try to commit to disk */
      dflfile = helper_build_meta_name(path, DFL_VERSION_PREFIX);
      if (write_default_file(dflfile, vid, svid) != 0)
        {
          free(dflfile);
          return -errno;
        }
      free(dflfile);
      
      /* If ok, change in RAM */
      metadata->md_dfl_vid = vid;
      metadata->md_dfl_svid = svid;
      
      /* remove deletion flag from metadata*/
      if (metadata->md_deleted)
      {
        metadata->md_deleted = 0;
        metafile = helper_build_meta_name(path, METADATA_PREFIX);
        if (write_metadata_file(metafile, metadata) != 0)
        {
          free(metafile);
          return -errno;
        }
        free(metafile);
      }

      return 0;
    }
  else if (!strcmp(name, "rcs.metadata_dump"))
    {
      /* This one is read-only */
      return -EPERM;
    }
  else
    {
      /* unknown rcs.*-attribute */
      return -EPERM;
    }
}



/*
 * Set the value of an extended attribute.
 */
int callback_setxattr(const char *path, const char *name, const char *value,
  size_t size, int flags)
{
  if (!strncmp(name, "rcs.", 4))
    {
      char *name_new, *path_new;
      int res;
      
      ea_prepare_data(path, name, &path_new, &name_new);
      res = ea_setxattr_rcs(path_new, name_new, value, size);
      
      free(path_new);
      free(name_new); 
      
      return res;
    }
  else
    {
      int res;
      metadata_t *metadata;
      version_t *version;
      
      metadata = rcs_translate_to_metadata(path, rcs_version_path);
      if (!metadata)
        return -ENOENT;
  
      /* Pass those through */
      version = rcs_find_version(metadata, LATEST, LATEST);
      if (!version)
        return -ENOENT;
      res = lsetxattr(version->v_rfile, name, value, size, flags);
      if (res == -1)
        return -errno;
      return 0;
    }
}

/*
 * Get the value of an extended attribute.
 */
int callback_getxattr(const char *path, const char *name, char *value,
  size_t size)
{
  if (!strncmp(name, "rcs.", 4))
    {
      char *name_new, *path_new;
      int res;
      
      ea_prepare_data(path, name, &path_new, &name_new);
      res = ea_getxattr_rcs(path_new, name_new, value, size);
    
      free(path_new);
      free(name_new); 
      
      return res;
    }
  else
    {
      int res;
      metadata_t *metadata;
      version_t *version;
      
      metadata = rcs_translate_to_metadata(path, rcs_version_path);
      if (!metadata)
        return -ENOENT;
      
      /*
       * We are not interested in those, simply forward them to the real
       * filesystem.
       */
      version = rcs_find_version(metadata, LATEST, LATEST);
      if (!version)
        return -ENOENT;
      res = lgetxattr(version->v_rfile, name, value, size);
      if (res == -1)
        return -errno;
      return res;
    }
}

/*
 * List the supported extended attributes.
 */
int callback_listxattr(const char *path, char *list, size_t size)
{
  char *rpath;
  int res;
  
  /* If we list our own attributes here, some programs will try to copy
   * them when copying files. That won't work:
   * - rcs.metadata_dump can't be copied, it is read-only
   * - rcs.purge can't be copied, it ist write-only
   * - rcs.locked_version CAN be copied, but this leads to unwantet results
   * So we just pass the attributes of the underlying filesystem.
   * 
   * Maybe this isn't the best solution, but it's better than letting some
   * programs fiddle around with file versions without knowing what they
   * are doing.*/

  rpath = rcs_translate_path(path, rcs_version_path);
  if (!rpath)
    return -ENOENT;

  /* Get the EAs of the real file */
  res = llistxattr(rpath, list, size);
  if (res == -1)
    res = -errno;
  free (rpath);
  return res;
}

/*
 * Remove an extended attribute.
 */
int callback_removexattr(const char *path, const char *name)
{
  if (!strcmp(name, "rcs.locked_version") ||
      !strcmp(name, "rcs.metadata_dump") ||
      !strcmp(name, "rcs.purge"))
    {
      /* Our attributes can't be deleted */
      return -EPERM;
    }
  else
    {
      char *rpath;
      int res;

      rpath = rcs_translate_path(path, rcs_version_path);
      res = lremovexattr(rpath, name);
      free(rpath);
      if (res == -1)
        return -errno;
      return 0;
    }
}
