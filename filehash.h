#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64 // For Linux on 32-platforms
#endif
#include <sys/stat.h>
#include <openssl/sha.h>
#include <stdbool.h>


// BSD-based OSX uses an argument to control the following of symbolic links; Linux uses separate system calls
#if __APPLE__
#define GETXATTR(a,b,c,d) getxattr((a),(b),(c),(d),0,XATTR_NOFOLLOW)
#define REMOVEXATTR(a,b) removexattr((a),(b),XATTR_NOFOLLOW)
#define SETXATTR(a,b,c,d,e) setxattr((a),(b),(c),(d),0,(e)|XATTR_NOFOLLOW)
#define FGETXATTR(a,b,c,d) fgetxattr((a),(b),(c),(d),0,0)
#define FSETXATTR(a,b,c,d,e) fsetxattr((a),(b),(c),(d),0,(e))
#define LISTXATTR(a,b,c) listxattr((a),(b),(c),XATTR_NOFOLLOW)
#define FLISTXATTR(a,b,c) flistxattr((a),(b),(c),XATTR_NOFOLLOW)
#else
#define GETXATTR(a,b,c,d) lgetxattr((a),(b),(c),(d))
#define REMOVEXATTR(a,b) lremovexattr((a),(b))
#define SETXATTR(a,b,c,d,e) lsetxattr((a),(b),(c),(d),(e))
#define FGETXATTR(a,b,c,d) fgetxattr((a),(b),(c),(d))
#define FSETXATTR(a,b,c,d,e) fsetxattr((a),(b),(c),(d),(e))
#define LISTXATTR(a,b,c) llistxattr((a),(b),(c))
#define FLISTXATTR(a,b,c) flistxattr((a),(b),(c))
#endif

#if __APPLE__
// Intel only! These really ought to be conditionally defined for ppc/intel
#define htole64(x) (x)
#define le64toh(x) (x)
#define st_mtim st_mtimespec

#endif


// Linux requires all user-space external attributes to be explicitly prefixed with "user."
#if __APPLE__
#define ATTR_NAME_256 "sha256"
#define ATTR_NAME_256OGG "sha256ogg"
#else
#define ATTR_NAME_256 "user.sha256"
#define ATTR_NAME_256OGG "user.sha256ogg"
#endif

// Darwin (OSX) has this, but Linux apparently doesn't
#ifndef MAP_NOCACHE
#define MAP_NOCACHE (0)
#endif

// Linux has this and OSX apparently doesn't
#ifndef MAP_POPULATE
#define MAP_POPULATE (0)
#endif

#ifndef O_NOATIME
#define O_NOATIME (0)
#endif

// How the free() library routine should have been all along: null the pointer after freeing!
#define FREE(p) (free(p), p = NULL)

enum tagstate { MISSING, OLD, CURRENT, NOT_APPLICABLE };

struct attr256 {
  struct timespec mtime;
  uint8_t hash[SHA256_DIGEST_LENGTH];
};

#define SHA256_MISMATCH 2
#define MISSING_TAGS 4

int hextobinary(uint8_t *out,char const *in,int bytes);
char *binarytohex(char *out,uint8_t const *in,int bytes);
long long copyfile(char const *source,char const *target);
int make_paths(char const *pathname,int mode);
int sha256_selftest(void);
long long update_tag_fd(int fd,struct stat const *);
long long update_ogg_tag_fd(int fd,struct stat const *statbuf);
int verify_tag_fd(int fd,struct stat const *);
int64_t hash_file(int fd,struct stat const *statbuf,void *sha256hash);
int64_t hash_ogg_file(int fd,void *sha256hash);
int getattr256(int fd,struct attr256 *attr,char const *name);
bool is_ogg_file(int fd);

// Compare two timespec structures
static inline int time_cmp(struct timespec const *a,struct timespec const *b){
  if(a->tv_sec > b->tv_sec)
    return +1;
  if(a->tv_sec < b->tv_sec)
    return -1;
  if(a->tv_nsec > b->tv_nsec)
    return +1;
  if(a->tv_nsec < b->tv_nsec)
    return -1;
  return 0;
}
