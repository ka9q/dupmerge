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
#include <ogg/ogg.h>

#include "filehash.h"

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
#if TRACE
    printf("oggsha256: %s\n",attr256ogg_state == CURRENT ? "current" : attr256ogg_state == OLD ? "old" : "missing");
#endif

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
#define OGG_BUFSZ 4096

  ogg_sync_state oy = {0};
  ogg_stream_state os = {0};
  ogg_page og = {0};
  ogg_packet op = {0};

  bool stream_initialized = false;
  int packet_index = 0;

  ogg_sync_init(&oy);

  int64_t byte_count = 0;
  for (;;) {
    char *buf = ogg_sync_buffer(&oy, OGG_BUFSZ);
    size_t n = fread(buf, 1, OGG_BUFSZ, fp);

    ogg_sync_wrote(&oy, n);

    while (ogg_sync_pageout(&oy, &og) == 1) {
      if (!stream_initialized) {
	int serial = ogg_page_serialno(&og);
	ogg_stream_init(&os, serial);
	stream_initialized = true;
      }
      ogg_stream_pagein(&os, &og);
      while (ogg_stream_packetout(&os, &op) == 1) {
	if (packet_index == 0) {
	  if (op.bytes < 8 || memcmp(op.packet, "OpusHead", 8) != 0) {
	    fprintf(stderr, "not OpusHead\n");
	    byte_count = -1;
	    goto done;
	  }
	} else if (packet_index == 1) {
	  if (op.bytes < 8 || memcmp(op.packet, "OpusTags", 8) != 0) {
	    fprintf(stderr, "not OpusTags\n");
	    byte_count = -1;
	    goto done;
	  }
	} else {
	  // This is one encoded Opus packet.
	  EVP_DigestUpdate(ctx,op.packet, op.bytes);
	  byte_count += op.bytes;
	}
	packet_index++;
      }
    }
    if (n == 0)
      break; // EOF

    if (ferror(fp)){
      byte_count = -1;
      break;
    }
  }
  done:;
    if (stream_initialized)
      ogg_stream_clear(&os);
    ogg_sync_clear(&oy);
    EVP_DigestFinal_ex(ctx,sha256hash,NULL);
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return byte_count;
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
