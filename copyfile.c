#define _GNU_SOURCE 1
// Must be defined before we include sys/stat.h on a 32-bit platform
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>

#include "filehash.h"

// Copy source file to target file, along with attributes, modes and owners
// Return number of bytes copied
// If error in copying data, delete target and return -1
// Errors in copying attributes or ownership are ignored
long long copyfile(char const *source,char const *target){
  long long bytes_copied = -1;

  int const fdi = open(source,O_RDONLY);
  if(fdi == -1)
    return -1;

  struct stat statbuf;
  if(fstat(fdi,&statbuf) == -1){
    // Should probably be an assert()
    int const errno_save = errno;
    close(fdi);
    errno = errno_save;
    return -1;
  }
  if(!S_ISREG(statbuf.st_mode)){
    close(fdi);
    errno = EISDIR;
    return -1; // Must be a regular file
  }
  int const fdo = open(target,O_RDWR|O_TRUNC|O_CREAT,statbuf.st_mode);
  if(fdo == -1){
    int const errno_save = errno;
    close(fdi);
    errno = errno_save;
    return -1;
  }
#if __linux__
  // Preallocate space, if possible
  fallocate(fdo,0,(off_t)0,statbuf.st_size);
#endif

  // Copy file
  char buffer[BUFSIZ];
  int len;
  while((len = read(fdi,buffer,BUFSIZ)) > 0){
    if(write(fdo,buffer,len) != len){
      len = -1;
      break;
    }
    bytes_copied += len;
  }
  if(len < 0) {
    int const errno_save = errno;
    close(fdo);
    close(fdi);
    unlink(target);
    errno = errno_save;
    return -1;
  }
  // Set modification and access times of copy to those of the original
  // These gratuitous differences between BSD/Linux/OSX are really annoying
#ifdef __APPLE__
  {
    struct timeval times[2] = {
      {.tv_sec = statbuf.st_atimespec.tv_sec,
       .tv_usec = statbuf.st_atimespec.tv_nsec / 1000
      },
      {.tv_sec = statbuf.st_mtimespec.tv_sec,
       .tv_usec = statbuf.st_mtimespec.tv_nsec / 1000
      }
    };
    futimes(fdo,times);
  }
#else
  {
    struct timespec times[2] = {statbuf.st_atim, statbuf.st_mtim};
    futimens(fdo,times);
  }
#endif

  // Copy any extended attributes
  int tagsize = 16384;
  char *taglist = malloc(tagsize);

  if((tagsize = FLISTXATTR(fdi,taglist,tagsize)) == -1 && errno == ERANGE){
    // Buffer for list of tags is too small, enlarge it and try again
    tagsize = FLISTXATTR(fdi,NULL,0); // get true size
    taglist = realloc(taglist,tagsize);
    assert(taglist != NULL);
    tagsize = FLISTXATTR(fdi,taglist,tagsize);
  }
  if(tagsize > 0){
    int attsize = 16384;
    char *attval = malloc(attsize);
    assert(attval != NULL);

    for(char const *tag = taglist; *tag != '\0'; tag += strlen(tag)){
      if((attsize = FGETXATTR(fdi,tag,attval,attsize)) == -1 && errno == ERANGE){
	// buffer too small for attribute, enlarge it and try again
	attsize = FGETXATTR(fdi,tag,NULL,0);
	attval = realloc(attval,attsize);
	assert(attval != NULL);
	attsize = FGETXATTR(fdi,tag,attval,attsize);
      } else if(attsize > 0){
	int const k = FSETXATTR(fdo,tag,attval,attsize,0);
	(void)k;
#if TRACE
	printf("setting tag %s return %d\n",tag,k);
#endif
      }
    }
    FREE(attval);
  }
  FREE(taglist);
  // Copy ownership
  fchown(fdo,statbuf.st_uid,statbuf.st_gid);

  // We're done
  close(fdi);
  close(fdo);
  return bytes_copied;
}

// Create any needed subdirectories in a pathname
int make_paths(char const *pathname,int mode){
  if(strlen(pathname) > PATH_MAX)
    return ENAMETOOLONG;

  char *workcopy = strdup(pathname);
  {
    char * const cp = strrchr(workcopy,'/');
    if(cp == NULL){
      // pathname is in current directory, nothing to do
      FREE(workcopy);
      return 0;
    }
    *cp = '\0'; // Leave just the directory prefix in workcopy
  }
  // Does the directory already exist?
  {
    struct stat statbuf;
    if(lstat(workcopy,&statbuf) == 0 && (statbuf.st_mode & S_IFMT) == S_IFDIR){
      // Everything appears honkey-dory
      FREE(workcopy);
      return 0;
    }
  }
  char *wp = workcopy;
  while(wp != NULL){
    char * const cp = strchr(wp,'/'); // Look for terminal / on current component
    if(cp != NULL){
      *cp = '\0'; // Temporarily end string here
      wp = cp+1;  // and look just beyond it on next iteration
    } else
      wp = NULL;  // this is the last iteration

    struct stat statbuf;
    if(lstat(workcopy,&statbuf) == -1){
      // try to make it
      if(mkdir(workcopy,mode) == -1){
	FREE(workcopy);
	return errno;
      }
    } else {
      // Stat succeeded; is it a directory?
      if((statbuf.st_mode & S_IFMT) != S_IFDIR){
	// No - error!
	FREE(workcopy);
	return ENOTDIR;
      }
    }
    // Restore the terminal / on the current component, go to the next
    if(cp != NULL)
      *cp = '/';
  }
  FREE(workcopy);
  return 0;
}
