// User-callable library for hash-based indexing
// Phil Karn, KA9Q
// Dec 2012
// Updated 2018 to add SHA256
// Updated Sept 2025 to remove SHA1, add sha256ogg

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

// Must be defined before we include sys/stat.h on a 32-bit platform
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <stdio.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>

#include "filehash.h"

// Read a SHA256 attribute in 3 formats:
// int32_t mtime, hash[32]
// int64_t mtime.tv_sec, int32_t mtime.tv_nsec, hash[32]
// int64_t mtime_tv.sec, int64_t mtime.tv_nsec, hash[32]

// Implicitly little endian, should add macros for portability to big-endian systems
int getattr256(int const fd,struct attr256 * const attr,char const *attr_name){
  uint8_t attrbuf[1024];
  int const length = FGETXATTR(fd,attr_name,&attrbuf,sizeof attrbuf);
  if(length == sizeof(int32_t) + SHA256_DIGEST_LENGTH){
    // Old version with 32-bit time_t and no nanoseconds
    attr->mtime.tv_sec = * (int32_t *)&attrbuf[0];
    attr->mtime.tv_nsec = 0;
    memcpy(attr->hash,&attrbuf[4],SHA256_DIGEST_LENGTH);
    return 0;
  } else if(length == sizeof(int64_t) + SHA256_DIGEST_LENGTH){
    // Old version with 64-bit time_t and no nanoseconds
    attr->mtime.tv_sec = * (int64_t *)&attrbuf[0];
    attr->mtime.tv_nsec = 0;
    memcpy(attr->hash,&attrbuf[8],SHA256_DIGEST_LENGTH);
    return 0;
  } else if(length == sizeof(int64_t) + sizeof(int32_t) + SHA256_DIGEST_LENGTH){
    // 8 + 4 format
    attr->mtime.tv_sec = * (int64_t *)&attrbuf[0];
    attr->mtime.tv_nsec = * (int32_t *)&attrbuf[8];
    memcpy(attr->hash,&attrbuf[12],SHA256_DIGEST_LENGTH);
    return 0;
  } else if(length == sizeof(int64_t) + sizeof(int64_t) + SHA256_DIGEST_LENGTH){
    // 8 + 8 format
    attr->mtime.tv_sec = * (int64_t *)&attrbuf[0];
    attr->mtime.tv_nsec = * (int64_t *)&attrbuf[8]; // Will truncate if host nsec is 4 bytes, that's OK
    memcpy(attr->hash,&attrbuf[16],SHA256_DIGEST_LENGTH);
    return 0;
  } else
    return -1;
}
// Temporarily enable write permissions so we can set an attribute
// May fail if we're not root or don't own the file
static int temp_enable(int const fd,struct stat const * const statbuf){
  // Simulate access() call to see if we'll have to temporarily enable write perms
  // This is hairy logic, I know
  int saved_mode = -1;
  uid_t const user_id = geteuid();
  gid_t const group_id = getegid();
  if(user_id != 0 && (
		      (user_id == statbuf->st_uid && !(statbuf->st_mode & S_IWUSR))
		      || (group_id == statbuf->st_gid && !(statbuf->st_mode & S_IWGRP))
		      || !(statbuf->st_mode & S_IWOTH)
		      )  ){
    // We need temporary write permission to change the tag
    saved_mode = statbuf->st_mode;
    if(fchmod(fd,saved_mode|S_IWUSR) == -1)
      return -1; // Probable permission failure
  }
  return saved_mode;
}

// Set sha256 attribute with name 'attr_name'
static int set_tag_256(int const fd, struct stat const *statbuf, struct attr256 const * const attr,
		       const char *attr_name){
  assert(fd != -1);

  struct stat sb = {0};
  if(statbuf == NULL){
    if(fstat(fd,&sb) == -1)
      return -1;
    statbuf = &sb;
  }
  int const saved_mode = temp_enable(fd,statbuf);
  uint8_t attrbuf[44];
  * (int64_t *)&attrbuf[0] = attr->mtime.tv_sec;
  * (int32_t *)&attrbuf[8] = (int32_t)attr->mtime.tv_nsec;
  memcpy(&attrbuf[12],attr->hash,SHA256_DIGEST_LENGTH);

  int const rval = FSETXATTR(fd,attr_name,attrbuf,sizeof attrbuf,0);

  int const errno_save = errno;  // Return errno (if any) of setxattr to caller
  if(saved_mode != -1)
    fchmod(fd,saved_mode);        // Restore mode

  errno = errno_save;
#if TRACE
  printf("set_tag_256: rval %d errno %d %s\n",rval,errno,rval != 0 ? strerror(errno):"");
#endif
  return rval;
}

// Take open file descriptor, update sha256 hash if out of date
long long update_tag_fd(int fd,struct stat const *statbuf){
  assert(fd != -1);

  struct stat sb = {0};
  if(statbuf == NULL){
    if(fstat(fd,&sb) == -1)
      return -1;
    statbuf = &sb;
  }

  if((statbuf->st_mode & S_IFMT) != S_IFREG)
    return -1; // Not regular file

  int64_t count = 0;

  {
    // Check status of flat, raw SHA256 tag (user.sha256)
    struct attr256 attr256 = {0};
    int attr256_state = MISSING;
    int const r = getattr256(fd,&attr256,ATTR_NAME_256);
    if(r == 0){
      if(time_cmp(&attr256.mtime,&statbuf->st_mtim) == 0){
	attr256_state = CURRENT;
      } else
	attr256_state = OLD;
    }
#if TRACE
    printf("sha256: %s",attr256_state == CURRENT ? "current" : attr256_state == OLD ? "old" : "missing");
#endif
    if(attr256_state == OLD || attr256_state == MISSING){
      count = hash_file(fd,statbuf,&attr256.hash);
#if TRACE
      printf(" hash_file returns %lld\n",(long long)count);
#endif
      attr256.mtime = statbuf->st_mtim;
      set_tag_256(fd,statbuf,&attr256,ATTR_NAME_256); // check return?
    }
  }
  return count;
}

long long update_ogg_tag_fd(int fd,struct stat const *statbuf){
  assert(fd != -1);

  struct stat sb = {0};
  if(statbuf == NULL){
    if(fstat(fd,&sb) == -1)
      return -1;
    statbuf = &sb;
  }
  if((statbuf->st_mode & S_IFMT) != S_IFREG)
    return -1; // Not regular file

  int64_t count = 0;

  // OGG-special hash with stream ID and CRCs zeroed (user.sha256ogg)
  // Check status of SHA256OGG tag
  struct attr256 attr256ogg = {0};
  int attr256ogg_state = MISSING;
  int const r = getattr256(fd,&attr256ogg,ATTR_NAME_256OGG);
  if(r == 0){
    if(time_cmp(&attr256ogg.mtime,&statbuf->st_mtim) == 0){
      attr256ogg_state = CURRENT;
    } else
      attr256ogg_state = OLD;
  }
  if(attr256ogg_state != CURRENT){
    count = hash_ogg_file(fd,&attr256ogg.hash);
#if TRACE
    printf(" hash_ogg_file returns %lld\n",(long long)count);
#endif
    if(count == -1){
      // Special tag for corrupt files to prevent continual rehashing
      // and errorneous deduplication
      memset(&attr256ogg.hash,0,SHA256_DIGEST_LENGTH);
    }
    attr256ogg.mtime = statbuf->st_mtim;
    set_tag_256(fd,statbuf,&attr256ogg,ATTR_NAME_256OGG); // check return?
  }
  return count;
}

// verify tags, if up to date
int verify_tag_fd(int const fd,struct stat const *statbuf){
  assert(fd != -1);

  struct stat sb = {0};
  if(statbuf == NULL){
    if(fstat(fd,&sb) == -1)
      return -1;
    statbuf = &sb;
  }
  if((statbuf->st_mode & S_IFMT) != S_IFREG)
    return -1; // Not regular file
  if(statbuf->st_nlink < 1)
    return 0;

#if TRACE
  printf("verify_tag_fd(%d) inode %lld size %lld",fd,(long long int)statbuf->st_ino,(long long int)statbuf->st_size);
#endif
  // Check status of SHA256 tag
  struct attr256 attr256 = {0};
  int attr256_state = MISSING;
  int const r = getattr256(fd,&attr256,ATTR_NAME_256);
  if(r == 0){
    if(time_cmp(&attr256.mtime,&statbuf->st_mtim) == 0){
      attr256_state = CURRENT;
    } else
      attr256_state = OLD;
  }
#if TRACE
  printf("sha256: %s,\n",attr256_state == CURRENT ? "current" : attr256_state == OLD ? "old" : "missing");
#endif

  // Verify only current hashes; ignore old and missing ones
  if(attr256_state != CURRENT)
    return MISSING_TAGS;

  struct attr256 new_attr256;

  long long const count = hash_file(fd,statbuf,(attr256_state == CURRENT) ? new_attr256.hash : NULL);
#if TRACE
  printf(" hash_file returns %lld\n",count);
#endif
  if(count == -1)
    return -1;

  int rval = 0;
  if(attr256_state == CURRENT && memcmp(attr256.hash,new_attr256.hash,sizeof new_attr256.hash) != 0){
    rval |= SHA256_MISMATCH;
  }
  // Need to also verify sha256ogg hashes, if present *****
  return rval;
}

// Compute conventional user.sha256 hash of entire file already open with file descriptor fd
int64_t hash_file(int const fd,struct stat const *statbuf,void * const sha256hash){
  assert(fd != -1);
  if(fd == -1){
    errno = EBADF;
    return -1;
  }
  struct stat sb = {0};
  if(statbuf == NULL){
    if(fstat(fd,&sb) == -1)
      return -1;
    statbuf = &sb;
  }
  if(sha256hash == NULL){
    errno = EINVAL;
    return -1;
  }
  // New EVP API used Aug 2025
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  assert(ctx != NULL);
  int r = EVP_DigestInit_ex(ctx,EVP_sha256(),NULL);
  (void)r;
  assert(r == 1);

  int64_t remain = statbuf->st_size;
  //  size_t chunksize = 512 * sysconf(_SC_PAGESIZE); // Matches a 2MB huge page on x86, might help
  int64_t chunksize = 1<<30;
  assert(chunksize != 0); // Make sure page size doesn't return 0
  int64_t count = 0;

  for(int64_t file_offset = 0;
      remain != 0;
      remain -= chunksize,file_offset += chunksize){
    chunksize = chunksize > remain ? remain : chunksize;
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif
    //    void * const p = mmap(NULL, chunksize, PROT_READ, MAP_NOCACHE|MAP_FILE|MAP_PRIVATE|MAP_POPULATE, fd, file_offset);
    void * const p = mmap(NULL, chunksize, PROT_READ, MAP_NOCACHE|MAP_FILE|MAP_PRIVATE, fd, file_offset);
    if(p == MAP_FAILED)
      return -1;
    //    madvise(p,chunksize,MADV_SEQUENTIAL|MADV_WILLNEED); // hopefully will cause OS to read everything ahead
    //    madvise(p,chunksize,MADV_SEQUENTIAL|MADV_WILLNEED); // hopefully will cause OS to read everything ahead
    madvise(p,chunksize,MADV_SEQUENTIAL); // hopefully will cause OS to read everything ahead
    int r = EVP_DigestUpdate(ctx,p,chunksize);
    (void)r;
    assert(r == 1);

    r = munmap(p,chunksize);
    assert(r != -1);
    count += chunksize;
  }
  r = EVP_DigestFinal_ex(ctx,sha256hash,NULL);
  assert(r == 1);
  EVP_MD_CTX_free(ctx);
  return count;
}
// Compute Ogg-special user.sha256ogg hash of entire ogg file already open with file descriptor fd
// Ogg page headers are read and stream ID and CRC are zeroed before hashing so files
// written separately will compare the same if their actual contents are the same
int64_t hash_ogg_file(int const fd,void * const sha256hash){
  if(fd == -1){
    errno = EBADF;
    return -1;
  }
  if(sha256hash == NULL){
    errno = EINVAL;
    return -1; // Nothing to do!
  }
  if (lseek(fd, 0, SEEK_SET) == (off_t)-1){
    errno = ESPIPE;
    assert(false);
    return -1;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  assert(ctx != NULL);
  {
    int const r = EVP_DigestInit_ex(ctx,EVP_sha256(),NULL);
    (void)r;
    assert(r == 1);
  }
  int const dfd = dup(fd); // fclose will close this
  FILE *fp = fdopen(dfd,"rb");
  if(fp == NULL){
    int esave = errno;
    close(dfd);
    EVP_MD_CTX_free(ctx);
    errno = esave;
    return -1;
  }
  // Process Ogg pages
  int64_t byte_count = 0;   // total byte count
  while(true){
    // Read page header
    uint8_t hdr[27];

    int const len = fread(hdr, 1, sizeof hdr, fp);
    if(len != sizeof hdr)
      break;
    if (memcmp(hdr, "OggS", 4) != 0)
      break;
    if (hdr[4] != 0)
      break;

    // Zero stream ID and CRC
    hdr[14] = hdr[15] = hdr[16] = hdr[17] = 0;
    hdr[22] = hdr[23] = hdr[24] = hdr[25] = 0;
    // Hash censored header
    {
      int const r = EVP_DigestUpdate(ctx,&hdr,sizeof hdr);
      (void)r;
      assert(r == 1);
    }
    byte_count += sizeof hdr;

    uint8_t const nseg = hdr[26];
    if (nseg != 0){
      uint8_t segtbl[255];
      if(fread(segtbl, 1, nseg, fp) != nseg)
	break;
      {
	int const r = EVP_DigestUpdate(ctx,segtbl,nseg);
	(void)r;
	assert(r == 1);
      }
      byte_count += nseg;
      unsigned int body_len = 0;
      for (unsigned i = 0; i < nseg; i++)
	body_len += segtbl[i];
      if (body_len > 255u * 255u)
	break;             // impossible, not sure why I'm testing for it

      if (body_len != 0) {
	uint8_t body[body_len]; // Larger than possible body (255 * 255 = 65025)
	if (fread(body, 1, body_len, fp) != body_len)
	  break;
	{
	  int const r = EVP_DigestUpdate(ctx,body,body_len);
	  (void)r;
	  assert(r == 1);
	}
	byte_count += body_len;
      }
    }
  }
  int const r = EVP_DigestFinal_ex(ctx,sha256hash,NULL);
  (void)r;
  assert(r == 1);
  EVP_MD_CTX_free(ctx);
  rewind(fp);
  fclose(fp);
  return byte_count;
}

// Convert hex-ascii string of arbitrary length to binary byte string
// Unknown characters are treated as 0's
// Caller must ensure space
int hextobinary(unsigned char * const restrict out,char const * restrict in,int const bytes){
  for(int i=0; i<bytes; i++){
    int bb = 0;
    char c = tolower(*in++);
    if(isdigit(c))
      bb = (unsigned)(c - '0') << 4;
    else if(isxdigit(c))
      bb = (unsigned)(c + 10 - 'a') << 4;
    c = tolower(*in++);
    if(isdigit(c))
      bb += (unsigned)(c - '0');
    else if(isxdigit(c))
      bb += (unsigned)(c + 10 - 'a');
    out[i] = bb;
  }
  return 0;
}
// Convert integer 0-15 to hex character 0-f
// Invalid values are converted to space
static inline char b2h(int const x){
  if(x >= 0 && x < 10)
    return '0' + x;
  else if(x < 16)
    return 'a' + (x - 10);
  else
    return ' ';
}
// Convert binary byte string to hex-ascii string, arbitrary length
// Terminate with null, return pointer to the null
// Caller must ensure space
char *binarytohex(char * restrict out, unsigned char const * restrict in, int const bytes){
  for(int i=0;i<bytes;i++){
    *out++ = b2h((in[i] >> 4) & 0xf);
    *out++ = b2h(in[i] & 0xf);
  }
  *out = '\0';
  return out;
}
// Paranoid check to ensure the hash functions aren't broken
// A broken hash function that returned the same value regardless of contents would be a disaster!
int sha256_selftest(void){
  static char const test_vector1[] = "abcdefghijklmnopqrstuvwxyz\n";
  static uint8_t test_vector1_hash[SHA256_DIGEST_LENGTH] = {
    0x10, 0x10, 0xa7, 0xe7, 0x61, 0x61, 0x09, 0x80, 0xac, 0x59,
    0x13, 0x59, 0xc8, 0x71, 0xf7, 0x24, 0xde, 0x15, 0x0f, 0x23,
    0x44, 0x0e, 0xbb, 0x59, 0x59, 0xac, 0x4c, 0x07, 0x24, 0xc9,
    0x1d, 0x91,
  };

  static char const test_vector2[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
  static uint8_t test_vector2_hash[SHA256_DIGEST_LENGTH] = {
    0xa0, 0x6b, 0x16, 0x8d, 0x8e, 0x72, 0xc0, 0x69, 0xaa, 0x3c, 0xc5,
    0x8d, 0x64, 0xb9, 0x2a, 0x30, 0x0f, 0x9f, 0x82, 0x12, 0x7f, 0xac,
    0xb3, 0x21, 0x98, 0x55, 0x05, 0x3e, 0x49, 0xa4, 0xec, 0xbe,
  };
  uint8_t hash[SHA256_DIGEST_LENGTH];
  SHA256((void *)test_vector1,strlen(test_vector1),hash);
  if(memcmp(hash,test_vector1_hash,SHA256_DIGEST_LENGTH) != 0){
    printf("SHA256 hash function self-test failed on test vector 1!\n");
    return -1;
  }
  SHA256((void *)test_vector2,strlen(test_vector2),hash);
  if(memcmp(hash,test_vector2_hash,SHA256_DIGEST_LENGTH) != 0){
    printf("SHA256 hash function self-test failed on test vector 2!\n");
    return -1;
  }
  return 0;
}
static uint32_t u32le(uint8_t const *p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint32_t ogg_crc32_update(uint32_t crc, uint8_t const *p, size_t n) {
  while (n--) {
    crc ^= (uint32_t)(*p++) << 24;              // feed MSB-first
    for (int i = 0; i < 8; i++)
      crc = (crc << 1) ^ (0x04C11DB7U & -(crc >> 31));
  }
  return crc;
}

bool is_ogg_file(int const fd) {
  if (fd < 0)
    return false;

  int const dupfd = dup(fd);                 // don’t consume caller’s fd
  if (dupfd < 0)
    return false;

  FILE *fp = fdopen(dupfd, "rb");
  if (!fp){
    close(dupfd);
    return false;
  }
  bool ok = false;
  uint8_t hdr[27];
  if (fread(hdr, 1, sizeof hdr, fp) != sizeof hdr)
    goto done;

  if (memcmp(hdr, "OggS", 4) != 0)
    goto done;        // capture

  if (hdr[4] != 0)
    goto done;                        // version 0 only

  uint8_t const header_type = hdr[5];
  if (!(header_type & 0x02))
    goto done;              // BOS must be set

  if (header_type & 0x01)
    goto done;                 // CONTINUED must be clear

  uint8_t nseg = hdr[26];
  if (nseg == 0)
    goto done;                          // first page must carry at least id packet

  uint8_t segtbl[255];
  if (fread(segtbl, 1, nseg, fp) != nseg)
    goto done;

  size_t body_len = segtbl[0];
  for (unsigned i = 1; i < nseg; i++)
    body_len += segtbl[i];
  if (body_len > 255u * 255u)
    goto done;             // impossible for Ogg

  if(body_len > 0){
    uint8_t body[body_len]; // longer than legal max
    if(fread(body, 1, body_len, fp) != body_len)
      goto done;

    // compute CRC over header (with crc field zeroed) + segtbl + body
    uint8_t hdr_crc[27];
    memcpy(hdr_crc, hdr, sizeof hdr_crc);
    memset(&hdr_crc[22], 0, 4);

    uint32_t crc = ogg_crc32_update(0,hdr_crc, 27);
    crc = ogg_crc32_update(crc,segtbl, nseg);
    crc = ogg_crc32_update(crc,body, body_len);
    uint32_t const stored = u32le(&hdr[22]);
    ok = ((uint32_t)crc == stored);
  }
 done:
  if (fp)
    fclose(fp);                 // also closes dupfd
  return ok;
}
