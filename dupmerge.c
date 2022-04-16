// $Id: dupmerge.c,v 1.5 2021/09/28 05:59:54 karn Exp $
/* Dupmerge - Reclaim disk space by deleting redundant copies of files and
 * creating hardlinks in their place

 * To build: gcc -o dupmerge -O2 dupmerge.c -l crypto
 * Uses the SHA hash functions in the openssl crypto library

 * This program reads from standard input, or generates from command line arguments, a list of files.
 * It then discovers which files have identical contents, unlinks all but one and recreates the other
 * path names as hard links to the remaining copy. Except when the -f option is used, identical files are discovered
 * regardless of directory path or file basename.

 * The input file list may be generated with a command like 'find . -print', or if the -0 option to dupmerge is used,
 * 'find . -print0'.

 * Non-plain files in the input (directories, pipes, devices, etc)
 * are ignored.  Identical files must be on the same file system to be linked.

 * Empty files are ignored by default because they are often used as locks or flags, and no disk space is reclaimed
 * by deleting them anyway.

 * Dupmerge prefers to keep the older of two identical files, as the older
 * timestamp is more likely to be the correct one given that many
 * copy utilities (e.g., 'cp') do not by default preserve modification
 * times.

 * Note: although this program will not lose any file contents or path name information, it will lose the inode information
 * in the unlinked copies. This includes file owner/group, modes and modification timestamps. For this reason, dupmerge is
 * best used on collections of files owned by a single user.

 * Command line arguments:
 * -0 Delimit file names with nulls rather than newlines; for use with 'find -print0'
 * -q Operate in quiet mode (otherwise, relinks are displayed on stdout)
 * -f Fast (very fast) mode that bypasses an exhaustive file comparison in favor of modification timestamps.
 *    If the two files are the same size, have the same basename and exactly the same timestamp, they're probably the same.
 *    Rsync uses this method by default and it seems to work well.
 * -t threshold_size (default 100,000 bytes); Apply the fast mode feature only to files larger than threshold_size
 * -n Dry run: simply list the actions that would be taken without actually unlinking or linking anything. Turns off -q.
 * -s By default, files are sorted in decreasing order of size so that the actual unlinking of duplicate files starts with
 *    the largest files. This recovers disk space as quickly as possible, but if for some reason you want to start with the
 *    smallest files, use this flag.
 * -L locale (default: en_US.UTF8) I added this because I'm going blind mentally inserting commas in big integers.

 * 2008: New algorithm. I no longer do the duplicate unlinking and relinking inside the qsort comparison routine.
 * It was a cute idea, but probably not as good as just producing a list of files, sorting it by size,
 * and running through that.

 * March 2009: the sort comparison function looks at the first page of each file when they're the same size.
 * This greatly reduces the number of comparisons done after the sort. Files with unique sizes are ignored. Files are
 * completely read at most once thanks to caching of their SHA1 hash values.

 * May 2010: simplify the algorithm (only one sort is performed) and fix bugs in the handling of more
 * than two identical copies of a single file. This version should reliably identify and link all identical copies.

 * Fall 2010: one or more directories and file names may be specified on the command line. In that case, dupmerge will explore
 * those directories and build the list itself instead of reading it from stdin.

 * Fall 2021: Significant rewrite. Simplify structure, use common library functions in library.c, switch to SHA256 hash
   Now requires extended file attribute support; always caches hashes in user.sha1/user.sha256 (Linux) or sha1/sha256 (MacOS)

 * Catch signals so that summary statistics can be produced when the program is aborted early.

 * Extra paranoia checks right before a pair of files is merged: if either file appears to have been modified since the
 * list was originally generated, dupmerge exits.

 * Trivia: this program was inspired by a cheating scandal in the introductory computer science course CS-100
 * at Cornell University the year after I graduated. The TAs simply sorted the projects by object code size and compared
 * those that were equal. That effectively found copies where only the variable names and comments had been changed.
 *
 * Copyright Phil Karn, karn@ka9q.net. http://www.ka9q.net
 * May be used under the terms of the GNU General Public License v 2.0
 * Many thanks to Simon Baatz for bug reports and fixes
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64 // For Linux on 32-platforms
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <sys/mman.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>
#include <openssl/sha.h>
#include <locale.h>
#include <dirent.h>
#include <signal.h>
#include <ftw.h>
#include <sys/xattr.h>

#include "filehash.h"

// BSD-based OSX uses an argument to control the following of symbolic links; Linux uses separate system calls
#if __APPLE__
#define GETXATTR(a,b,c,d) getxattr((a),(b),(c),(d),0,XATTR_NOFOLLOW)
#define REMOVEXATTR(a,b) removexattr((a),(b),XATTR_NOFOLLOW)
#define SETXATTR(a,b,c,d,e) setxattr((a),(b),(c),(d),0,(e)|XATTR_NOFOLLOW)
#define FGETXATTR(a,b,c,d) fgetxattr((a),(b),(c),(d),0,0)
#define FSETXATTR(a,b,c,d,e) fsetxattr((a),(b),(c),(d),0,(e))
#else
#define GETXATTR(a,b,c,d) lgetxattr((a),(b),(c),(d))
#define REMOVEXATTR(a,b) lremovexattr((a),(b))
#define SETXATTR(a,b,c,d,e) lsetxattr((a),(b),(c),(d),(e))
#define FGETXATTR(a,b,c,d) fgetxattr((a),(b),(c),(d))
#define FSETXATTR(a,b,c,d,e) fsetxattr((a),(b),(c),(d),(e))
#endif

/* Darwin (OSX) has this, but Linux apparently doesn't */
#ifndef MAP_NOCACHE
#define MAP_NOCACHE (0)
#endif
/* Linux has this and OSX apparently doesn't */
#ifndef MAP_POPULATE
#define MAP_POPULATE (0)
#endif

int Nopenfd = 100;

enum flag { NO=0,YES=1,UNKNOWN=-1 };

enum flag Fast_flag = NO;
enum flag Zero_flag = NO;
enum flag Quiet_flag = NO;
enum flag Fast_threshold = 100000;
enum flag No_do = NO;
enum flag Small_first = NO;
unsigned long long Minimum_size = 1; // 1 byte minimum

int Verbose;
int Progress;

/* Statistics counts */
unsigned long long Regular_file;
unsigned long long FIFO;
unsigned long long Character_special;
unsigned long long Directory;
unsigned long long Block_special;
unsigned long long Symbolic_link;
unsigned long long Socket;
unsigned long long Whiteout;
unsigned long long Unknown;
unsigned long long Null_pathname;
unsigned long long Total_files;
unsigned long long Empty;
unsigned long long Too_small;
unsigned long long Stat_fail;
unsigned long long Not_accessible;
unsigned long long Files_deleted;
unsigned long long Unique_sizes;
unsigned long long Extra_links;
unsigned long long Hard_links;
unsigned long long Blocks_reclaimed;
unsigned long long Hashes_computed;
unsigned long long Hashes_fetched;
unsigned long long Hash_fail;
unsigned long long Unlinks;
unsigned long long Unlink_failures;

size_t pagesize;
size_t mapchunk;

char *Program_name; // Points to argv[0], for benefit of subroutines generating error messages

#define ENTRYCHUNK 5000 // Allocation unit for file table
#define MAP_PAGES 32768 // Number of pages to mmap on each loop


struct timespec Epoch = {
  0,0,
};


// File table entry
struct entry {
  char *pathname; // Path name, reserved space for null
  struct stat statbuf; // file i-node data
  struct attr256 attr256;
  int attr_present;
};

void print_stats(void);
void sig_handler(int);

// Comparison functions
int comparison_equal(const void *ap,const void *bp); // Does most of the work
int comparison_sort(const void *ap,const void *bp); // Version called by qsort()
int compare_inodes(const void *ap,const void *bp); // Version called by qsort()
int compare_extents(const void *ap,const void *bp);

struct entry *Entries; // Dynamically allocated file table
unsigned int Entryarraysize; // Start with empty table, allocate on first pass
unsigned int Nfiles; // Actual number of entries in Entries[]

void dump_files(void);
void dump_entry(struct entry *);
int get_big_hash(struct entry *ep,struct stat const *);
// Our function that will handle each file in the hierarchy
int process(const char *pathname,const struct stat *statbuf,int typeflag,struct FTW *ftwbuf);


int main(int argc,char *argv[]){
  int i,j;
  char *locale_string = "en_US.UTF-8";
  int c;

  Program_name = argv[0];

  assert(sha256_selftest() == 0);

  // Determine system page size and amount to map each time
  pagesize = sysconf(_SC_PAGESIZE);
  pagesize = pagesize > 0 ? pagesize : 4096; // If it fails, default to 4096 (x86 page size)
  mapchunk = MAP_PAGES * pagesize; // Amount to hash at one time in full file hash

  // Process command line args
  while((c = getopt(argc,argv,"snqf0t:L:vm:")) != EOF){
    switch(c){
    case 'm':
      Minimum_size = strtoll(optarg,NULL,0);
      break;
    default:
      printf("Usage: %s [-i interval] [-v] [-m minsize] [-s] [-n] [-q] [-f] [-0] [-L locale] [-t threshold_size]\n",Program_name);
      break;
    case 'L':
      locale_string = optarg;
      break;
    case 's':
      Small_first = YES;
      break;
    case 'n':
      No_do = YES;
      break;
    case 'q':
      Quiet_flag = YES;
      break;
    case 'f':
      Fast_flag = YES; /* Just compare modification timestamps, not file contents */
      break;
    case '0':
      Zero_flag = YES; /* Path names are delimited by nulls, e.g., from 'find . -print0' */
      break;
    case 't':
      Fast_threshold = atoi(optarg);
      break;
    case 'v':
      Verbose++;
      break;
    }
  }
  if(NULL == setlocale(LC_NUMERIC,locale_string))
    printf("setlocale %s failed\n",locale_string);

  if(No_do && Quiet_flag){
    printf("%s: -q flag forced off with -n set\n",Program_name);
    Quiet_flag = NO; /* Force off */
  }
  // Catch signals so we can show statistics if the user hits ^C
  signal(SIGHUP,sig_handler);
  signal(SIGINT,sig_handler);
  signal(SIGQUIT,sig_handler);
  signal(SIGILL,sig_handler);
  signal(SIGABRT,sig_handler);
  signal(SIGBUS,sig_handler);
  signal(SIGSEGV,sig_handler);
  signal(SIGSYS,sig_handler);
  signal(SIGPIPE,sig_handler);
  signal(SIGTERM,sig_handler);
  signal(SIGXCPU,sig_handler);
  signal(SIGXFSZ,sig_handler);
  signal(SIGVTALRM,sig_handler);
  signal(SIGPROF,sig_handler);
  signal(SIGUSR1,sig_handler);
  signal(SIGUSR2,sig_handler);

  // Process directories given as command-line arguments
  if(optind < argc){
    int i;

    for(i=optind;i<argc;i++)
      nftw(argv[i],process,Nopenfd,FTW_PHYS);

  } else {
    // If no directories on command line, read list of files from stdin
    while(!feof(stdin)){
      int ch,i;
      char pathname[PATH_MAX+1];

      for(i=0;i< PATH_MAX;i++){
	if(EOF == (ch = getc(stdin)) || '\0' == ch || (!Zero_flag && '\n' == ch))
	  break;
	pathname[i] = ch;
      }
      pathname[i] = '\0';
      nftw(pathname,process,Nopenfd,FTW_PHYS);
    }
  }

  // Display file statistics
  if(!Quiet_flag){
    printf("%s: input files: total %'llu; ordinary %'llu",Program_name,Total_files,Regular_file);
    if(FIFO)
      printf("; FIFO %'llu",FIFO);
    if(Character_special)
      printf("; char special %'llu",Character_special);
    if(Directory)
      printf("; directories %'llu",Directory);
    if(Block_special)
      printf("; block specials %'llu",Block_special);
    if(Symbolic_link)
      printf("; symbolic links %'llu",Symbolic_link);
    if(Socket)
      printf("; sockets %'llu",Socket);
    if(Whiteout)
      printf("; whiteouts %'llu",Whiteout);
    if(Empty)
      printf("; empties %'llu",Empty);
    if(Too_small)
      printf("; too small %'llu",Too_small);
    if(Unknown)
      printf("; unknown %'llu",Unknown);
    putc('\n',stdout);

    if(Null_pathname)
      printf("%s: null pathnames %'llu\n",Program_name,Null_pathname);

    if(Stat_fail)
      printf("%s: stat failures %'llu\n",Program_name,Stat_fail);

    if(Not_accessible)
      printf("%s: files not accessible %'llu\n",Program_name,Not_accessible);

    if(Nfiles == 0)
      printf("%s: no files left to examine\n",Program_name);
  }
  if(Nfiles < 2)
    exit(0); // Nothing to do!

#if DEBUG
  dump_files();
#endif

  if(No_do)
    printf("%s: dry run, no files will actually be unlinked\n",Program_name);
  
  /* Sort by file size/device/mod time/nlinks */
  qsort(Entries,Nfiles,sizeof(struct entry),comparison_sort);
  if(Verbose)
    printf("%s: sort done, %'u entries on list\n",Program_name,Nfiles);
    
#if DEBUG
  dump_files();
#endif

  // Walk through file list culling out redundant hard links
  // This is only performed for the first (oldest) entry of a given size on a device; if other files of the
  // same size follow, we must leave them all because it's possible we'll have to merge all those
  // path names to the first one. This still takes care of the common case where all the entries
  // of a given size refer to a single file
  for(i=0;i<Nfiles;i = j){
    for(j=i+1; j<Nfiles &&
	  Entries[i].statbuf.st_size == Entries[j].statbuf.st_size &&
	  Entries[i].statbuf.st_dev == Entries[j].statbuf.st_dev &&
	  Entries[i].statbuf.st_ino == Entries[j].statbuf.st_ino; j++){
      // Already hard linked, remove from list
      free(Entries[j].pathname);
      Entries[j].pathname = NULL;
      Extra_links++;
    }
    // Skip any more files with the same size on the same device
    for(;j<Nfiles && Entries[i].statbuf.st_size == Entries[j].statbuf.st_size &&
	  Entries[i].statbuf.st_dev == Entries[j].statbuf.st_dev;j++)
      ; // empty loop body

  }
  if(Extra_links != 0){
    if(Verbose)
      printf("%s: %'llu redundant hard links removed from list\n",Program_name,Extra_links);
    
    qsort(Entries,Nfiles,sizeof(struct entry),comparison_sort);
    Nfiles -= Extra_links;
    if(Verbose)
      printf("%s: list resorted, %'u entries left\n",Program_name,Nfiles);
    
    if(Nfiles < 2){
      free(Entries);
      exit(0);
    }
  }
  // Walk through file list culling out unique sizes
  for(i=0;i<Nfiles;i = j){
    // Find first file after this one with a different size or device
    for(j=i+1; j<Nfiles &&
	  Entries[i].statbuf.st_size == Entries[j].statbuf.st_size &&
	  Entries[i].statbuf.st_dev == Entries[j].statbuf.st_dev; j++){
      // empty body
    }
    if(j == i+1){
      // Unique size on this device, remove from list
      free(Entries[i].pathname);
      Entries[i].pathname = NULL;
      Unique_sizes++;
    }
  }

  if(Unique_sizes != 0){
    if(Verbose)
      printf("%s: %'llu files with unique sizes removed from list\n",Program_name,Unique_sizes);
    
    qsort(Entries,Nfiles,sizeof(struct entry),comparison_sort);
    Nfiles -= Unique_sizes;
    if(Verbose)
      printf("%s: list resorted, %'u entries left\n",Program_name,Nfiles);
    
    if(Nfiles < 2){
      free(Entries);
      exit(0);
    }
  }    
  // Walk through first of each group of files that are candidates for being the same
  // This is the reference file
  for(i=0;i<Nfiles-1;i++){
    
    Progress = i;

    // Ignore hard links to earlier reference files
    if(Entries[i].pathname == NULL)
      continue;

    // The qsort grouped together all files with the same size on the same device
    // Scan forward for all files with the same size and device as the reference file
    for(j=i+1;
	j<Nfiles
	  && Entries[i].statbuf.st_size == Entries[j].statbuf.st_size
	  && Entries[i].statbuf.st_dev == Entries[j].statbuf.st_dev;
	j++){
      
      
      if(Entries[j].pathname == NULL)
	continue;

      if(Entries[i].statbuf.st_dev == Entries[j].statbuf.st_dev
	 && Entries[i].statbuf.st_ino == Entries[j].statbuf.st_ino){
	// Existing hard link to reference file; mark so we'll skip over it later
	free(Entries[j].pathname);
	Entries[j].pathname = NULL;
	continue;
      }
      if(comparison_equal(&Entries[i],&Entries[j]) == 0){
	// Distinct files with identical contents on same file system, can be linked
	if(Verbose){
	  printf("%s: %'llu ln %s -> %s\n",Program_name,(unsigned long long)Entries[j].statbuf.st_size,Entries[j].pathname,Entries[i].pathname);
#if DEBUG
	  printf("debug: inodes %'llu %'llu\n",(unsigned long long)Entries[j].statbuf.st_ino,(unsigned long long)Entries[i].statbuf.st_ino);
#endif
	}
	if(Entries[j].statbuf.st_nlink == 1){
	  // Pathname has single remaining link, so its blocks will be recovered
	  Blocks_reclaimed += Entries[j].statbuf.st_blocks;
	}
	
	{
	  // Some last minute paranoid checks
	  struct stat statbuf_a,statbuf_b;
	  
	  if(lstat(Entries[i].pathname,&statbuf_a)){
	    printf("%s: can't lstat(%s): %d %s\n",Program_name,Entries[i].pathname,errno,strerror(errno));
	    abort();
	  }
	  if(lstat(Entries[j].pathname,&statbuf_b)){
	    printf("%s: can't lstat(%s): %d %s\n",Program_name,Entries[j].pathname,errno,strerror(errno));
	    abort();
	  }
	  // ensure file hasn't been modified
	  if(statbuf_a.st_size != Entries[i].statbuf.st_size || time_cmp(&statbuf_a.st_mtim,&Entries[i].statbuf.st_mtim)){
	    printf("%s: %s has changed; restart program\n",Program_name,Entries[i].pathname);
	    goto done;
	  }
	  if(statbuf_b.st_size != Entries[j].statbuf.st_size || time_cmp(&statbuf_b.st_mtim,&Entries[j].statbuf.st_mtim)){
	    printf("%s: %s has changed; restart program\n",Program_name,Entries[j].pathname);
	    goto done;
	  }

	  assert(statbuf_a.st_size == statbuf_b.st_size);
	  assert(statbuf_a.st_ino != statbuf_b.st_ino);
	  assert(statbuf_a.st_dev == statbuf_b.st_dev);
	  // the epoch sorts after all other times because mtimes can sometimes be set to it by error
	  assert(time_cmp(&Epoch,&statbuf_b.st_mtim) == 0 || time_cmp(&statbuf_b.st_mtim,&statbuf_a.st_mtim) >= 0);
	}
	if(!No_do){
	  if(unlink(Entries[j].pathname)) {
	    Unlink_failures++;
	    printf("%s: can't unlink(%s): %d %s\n",Program_name,Entries[j].pathname,errno,strerror(errno));
	  } else if(link(Entries[i].pathname,Entries[j].pathname)){
	    // Should never fail if unlink succeeded
	    printf("%s: can't link(%s,%s): %d %s\n",Program_name,Entries[i].pathname,Entries[j].pathname,errno,strerror(errno));
	    abort();
	  }
	}
	// Don't use this entry as a reference file later
	free(Entries[j].pathname);
	Entries[j].pathname = NULL;
	Unlinks++;
      } // if same
    } // End of inner for() loop
  } // end of for loop looking ahead for match with file i
 done:;
  print_stats();
  free(Entries);  // Not really necessary since we're exiting
  exit(0);
}


// Process a path name
// if it's an ordinary, readable, non-empty file, add it to the list
// if it's a directory, process it recursively
// Otherwise, ignore it
int process(const char *pathname,const struct stat *statbuf,int typeflag,struct FTW *ftwbuf){
  struct entry *ep;
  assert(statbuf != NULL);

  Total_files++;

  // Ignore null path names
  if(pathname == NULL || strlen(pathname) == 0){
    Null_pathname++;
    return 0;
  }
  if(typeflag == FTW_NS){
    Stat_fail++;
    if(Verbose > 1)
      printf("%s: stat failed!\n",pathname);
    return 0; // Stat() failed, no analysis possible
  }
  // Count but otherwise ignore special files: FIFOs, block special, character special, sockets, whitespace
  switch(statbuf->st_mode & S_IFMT){
  case S_IFIFO:
    FIFO++;
    if(Verbose > 1)
      printf("%s: FIFO\n",pathname);
    return 0;
  case S_IFBLK:
    Block_special++;
    if(Verbose > 1)
      printf("%s: block special\n",pathname);
    return 0;
  case S_IFCHR:
    Character_special++;
    if(Verbose > 1)
      printf("%s: char special\n",pathname);
    return 0;
  case S_IFSOCK:
    Socket++;
    if(Verbose > 1)
      printf("%s: socket\n",pathname);
    return 0;
#ifdef S_IFWHT
  case S_IFWHT:
    Whiteout++;
    if(Verbose > 1)
      printf("%s: whiteout\n",pathname);
    return 0;
#endif
  case S_IFREG:
    Regular_file++;
    break;
  case S_IFLNK:
    Symbolic_link++;
    break;
  case S_IFDIR:
    Directory++;
    if(Verbose > 1)
      printf("%s: Directory\n",pathname);
    return 0;
  default:
    Unknown++;
    if(Verbose > 1)
      printf("%s: unknown type (0%o)\n",pathname,statbuf->st_mode & S_IFMT);
    return 0;
  }

  if(typeflag != FTW_F)
    return 0; // Ignore all but ordinary files

  if(statbuf->st_blocks == 0){
    // Ignore files with no assigned data blocks (any data being stored in the inode).
    // Zero size files are often used as flags and locks we don't want to upset. And we won't recover
    // any data blocks from a file without any data blocks!
    // I should also exclude HFS files on OSX with resource forks
    if(Verbose > 1)
      printf("%s: empty\n",pathname);
    Empty++;
    return 0;
  }
  if(statbuf->st_size < Minimum_size){
    if(Verbose > 1)
      printf("%s: too small\n",pathname);
    Too_small++;
    return 0;
  }


  // Ordinary file; add to file table
  // Expand file table if necessary and possible
  if(Nfiles >= Entryarraysize){
    Entries = (struct entry *)realloc(Entries,(Entryarraysize + ENTRYCHUNK) * sizeof(struct entry));
    assert(Entries != NULL);
    Entryarraysize += ENTRYCHUNK;
  }
  ep = &Entries[Nfiles];
  ep->statbuf = *statbuf;
  ep->pathname = strdup(pathname);

  Nfiles++;

#if DEBUG
  dump_entry(ep);
#endif
  return 0;
}

// Compare files by size (used by second sort)
// Return 0 means same size *and* on same device
// Returning <0 causes the first argument to sort toward the top of the list
// Returning >0 causes the second argument to sort toward the top of the list

// We want the largest files to go to the top of the list, so "smaller is greater".
// We also want empty entries to go to the end of the list, so they are always "greater" 
int comparison_sort(const void *ap,const void *bp){
  struct entry *a,*b;

  a = (struct entry *)ap;
  b = (struct entry *)bp;

  // These aren't really illegal, but qsort should never pass null entries, or try to compare an entry with itself
  assert(a != NULL);
  assert(b != NULL);
  assert(a != b);

  // Null pathnames indicate cleared entries marked for deletion; push them to the bottom of the sort
  if(!b->pathname)
    return -1;
  else if(!a->pathname)
    return 1;

  // Each non-cleared entry has a unique path name, and qsort should never compare an entry with itself
  assert(b->pathname != a->pathname);
  
  // Distinguish first by size.
  // By default, bigger files sort first unless overridden with -s option
  if(b->statbuf.st_size != a->statbuf.st_size){
    if(Small_first)
      return a->statbuf.st_size > b->statbuf.st_size? +1 : -1;
    else
      return a->statbuf.st_size > b->statbuf.st_size? -1 : +1;
  }
  // Files are same size; distinguish if on different device; ordering is unimportant
  if(b->statbuf.st_dev != a->statbuf.st_dev)
    return b->statbuf.st_dev > a->statbuf.st_dev ? +1 : -1;

  // Same size, same device; distinguish by modification time, older files first
  // Exception: the epoch (0) is considered to come *after* all other times, as mtimes sometimes get zeroed and we don't
  // want to lose a non-zero mtime that's more likely correct
  if(time_cmp(&a->statbuf.st_mtim,&b->statbuf.st_mtim) != 0){
    if(time_cmp(&Epoch,&a->statbuf.st_mtim) == 0) // epoch; comes after everything
      return +1;
    else if(time_cmp(&Epoch,&b->statbuf.st_mtim) == 0)
      return -1;
    else return time_cmp(&a->statbuf.st_mtim,&b->statbuf.st_mtim);
  }
  // Order equal, same time files with fewer links later so they'll be preferentially deleted sooner
  if(a->statbuf.st_nlink != b->statbuf.st_nlink)
    return b->statbuf.st_nlink > a->statbuf.st_nlink? +1 : -1;

  // Same size, same device, same modification time, same number of links; includes case of two links to same inode
  return 0;
}



int comparison_equal(const void *ap,const void *bp){
  struct entry *a,*b;
  int i;

  a = (struct entry *)ap;
  b = (struct entry *)bp;

  if(a == b)
    return 0; /* Can this happen? */

  assert(a != NULL);
  assert(b != NULL);

  // If the files are hard linked, they're the same. This "can't happen" because we've already
  // checked for it, but to be safe...
  if(a->statbuf.st_dev == b->statbuf.st_dev && a->statbuf.st_ino == b->statbuf.st_ino)
    return 0;

  // Make file size the most significant part of the comparison
  if(b->statbuf.st_size != a->statbuf.st_size)
    return b->statbuf.st_size > a->statbuf.st_size ? +1 : -1;

  // Same-size files sort together only when they're on the same device
  if(b->statbuf.st_dev != a->statbuf.st_dev)
    return b->statbuf.st_dev > a->statbuf.st_dev ? +1 : -1;

  // Optionally use the rsync heuristic -- if the files have the same size, mod timestamp and
  // the same base name, declare them the same without actually reading the contents
  // Do this only on files larger than Fast_threshold to further reduce chances of false equality
  if(Fast_flag && a->statbuf.st_size > Fast_threshold){	// Rsync-style fast comparison
    char *bn1,*bn2;
    
    // I could use the built-in basename() function, but what a mess it is
    if((bn1 = strrchr(a->pathname,'/')) == NULL)
      bn1 = a->pathname;
    if((bn2 = strrchr(b->pathname,'/')) == NULL)
      bn2 = b->pathname;
    
    // Are the basenames and mod times identical?
    // Also require that the mod time isn't the epoch (0), which sometimes happens to a lot of files and could cause
    // false equality
    if(time_cmp(&Epoch,&a->statbuf.st_mtim) != 0 && 0 == strcmp(bn1,bn2) && time_cmp(&a->statbuf.st_mtim,&b->statbuf.st_mtim) == 0)
      return 0;
  }

  // compare full file hashes
  get_big_hash(a,&a->statbuf);
  get_big_hash(b,&b->statbuf);
  
  i = memcmp(a->attr256.hash,b->attr256.hash,sizeof(a->attr256.hash));
  if(i != 0)
    Hash_fail++;

  return i; // full hash comparison is final and authoritative
}

int compare_inodes(const void *ap,const void *bp){
  struct entry *a,*b;

  a = (struct entry *)ap;
  b = (struct entry *)bp;

  if(a == NULL && b == NULL)
    return 0;
  else if(a == NULL && b != NULL)
    return -1;
  else if(a != NULL && b == NULL)
    return -1;

  if(a->statbuf.st_dev > b->statbuf.st_dev)
    return +1;
  else if(a->statbuf.st_dev < b->statbuf.st_dev)
    return -1;

  if(a->statbuf.st_ino > b->statbuf.st_ino)
    return +1;
  else if(a->statbuf.st_ino < b->statbuf.st_ino)
    return -1;

  return 0; // The files are linked
}



// Fill in the filehash[] field in the file entry structure
// We can get it from three places:
// 1. If the small hash is available and the file is not larger than Small_hash_size (default 4kiB = 1 page on the x86),
//    then we can just copy it over
// 2. The hash can be cached from a previous run in the user.sha1 extended attribute on the file. Not all filesytems support
//    extended attributes; I developed this specifically for XFS
// 3. Last but not least, we can compute the full file hash ourselves
//   
// In cases 1 & 3 we'll store the hash to the user.sha1 for future use
int get_big_hash(struct entry *ep,struct stat const *statbuf){
  if(ep->attr_present)
    return 0;
  int rval = 0;
  int fd = open(ep->pathname,O_RDONLY);
  if(fd == -1){
    rval = -1;
    if(Verbose)
      printf("Can't read %s: %s\n",ep->pathname,strerror(errno));
    goto done;
  }
  // Ensure tag is present and up to date
  long long r = update_tag_fd(fd,statbuf);
  if(r < 0){
    rval = -1;
    if(Verbose)
      printf("update_tag_fd(%s) failed:%s\n",ep->pathname,strerror(errno));
    goto done;
  }
  if(r > 0)
    Hashes_computed++;

  if(getattr256(fd,&ep->attr256) == -1){
    rval = -1;
    if(Verbose)
      printf("%s: error getting attribute: %s\n",ep->pathname,
	      strerror(errno));
    goto done;
  }
  Hashes_fetched++;
  ep->attr_present = 1;
 done:;
  if(fd != -1)
    close(fd);
  return rval;
}
void dump_entry(struct entry *ep){

#if (__darwin__)
  printf(" inode %'llu; links %u; uid %d; gid %d; atime %ld.%09ld; mtime %ld.%09ld; ctime %ld.%09ld; size %'llu; gen %d; %s\n",
	  ep->statbuf.st_ino,
	  (unsigned int)ep->statbuf.st_nlink,ep->statbuf.st_uid,ep->statbuf.st_gid,
	  ep->statbuf.st_atimespec.tv_sec,ep->statbuf.st_atimespec.tv_nsec,
	  ep->statbuf.st_mtimespec.tv_sec,ep->statbuf.st_mtimespec.tv_nsec,
	  ep->statbuf.st_ctimespec.tv_sec,ep->statbuf.st_ctimespec.tv_nsec,
	  (unsigned long long)ep->statbuf.st_size,ep->statbuf.st_gen,ep->pathname);
#elif(__linux__)
  printf(" inode %'llu; links %u; uid %d; gid %d; atime %ld.%09ld; mtime %ld.%09ld; ctime %ld.%09ld; size %'llu; %s\n",
	 (long long unsigned)ep->statbuf.st_ino,
	 (unsigned int)ep->statbuf.st_nlink,ep->statbuf.st_uid,ep->statbuf.st_gid,
	 ep->statbuf.st_atim.tv_sec,ep->statbuf.st_atim.tv_nsec,
	 ep->statbuf.st_mtim.tv_sec,ep->statbuf.st_mtim.tv_nsec,
	 ep->statbuf.st_ctim.tv_sec,ep->statbuf.st_ctim.tv_nsec,
	 (unsigned long long)ep->statbuf.st_size,ep->pathname);
#else
  printf(" inode %'llu; links %u; uid %d; gid %d; atime %ld; mtime %ld; ctime %ld; size %'llu; %s\n",
	  (unsigned long long) ep->statbuf.st_ino,
	  (unsigned int)ep->statbuf.st_nlink,ep->statbuf.st_uid,ep->statbuf.st_gid,
	  ep->statbuf.st_atime,
	  ep->statbuf.st_mtime,
	  ep->statbuf.st_ctime,
	  (unsigned long long)ep->statbuf.st_size,
	  ep->pathname);
#endif
}


void dump_files(void){
  int i;

  for(i=0;i<Nfiles;i++)
    dump_entry(&Entries[i]);
}

void print_stats(void){
  if(!Quiet_flag){
    if(No_do)
      printf("%s: This is a dry run; no files were actually unlinked.\n",Program_name);
    if(Unlinks)
      printf("%s: Unlinks: %'llu; Unlink failures: %'llu; disk blocks reclaimed: %'llu\n",Program_name,Unlinks,Unlink_failures,Blocks_reclaimed);
    
    printf("%s: Hashes computed: %'llu; fetched from tags: %'llu; mismatches: %'llu\n",Program_name,Hashes_computed,Hashes_fetched,Hash_fail);
  }
}

void sig_handler(int sig){
  printf("%s: Signal %d\n",Program_name,sig);
  print_stats();
  exit(1);
}
