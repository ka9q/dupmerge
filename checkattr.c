// Walk through file system updating and checking SHA1/256 tags
// Phil Karn, KA9Q
// Apr 2018
// New unified SHA1/SHA256 version May 2020
// $Id: checkattr.c,v 1.35 2022/04/25 07:55:15 karn Exp karn $

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64 // For Linux on 32-platforms
#endif



#include <stdio.h>
#include <sys/time.h>
#include <ftw.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <limits.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <locale.h>
#include <signal.h>
#include <time.h>
#include <utime.h>

#include "filehash.h"


#ifndef FTW_ACTIONRETVAL
#define FTW_ACTIONRETVAL (16)
#endif

#ifndef FTW_CONTINUE
#define FTW_CONTINUE (0)
#endif

#ifndef FTW_STOP
#define FTW_STOP (1)
#endif

#ifndef FTW_SKIP_SUBTREE
#define FTW_SKIP_SUBTREE (2)
#endif

#ifndef FTW_SKIP_SIBLINGS
#define FTW_SKIP_SIBLINGS (3)
#endif

int Nopenfd = 100;

// Command-line options and flags, with defaults
int Zero_flag; // Interpret '\0' as delimiter on file names read from stdin
int Check_tags; // Verify correctness of all existing, up-to-date tags
int Quiet; // Be very quiet except for fatal errors

// Statistics counters
// Counts of file types seen
unsigned long long Regular_files;
unsigned long long FIFO;
unsigned long long Character_special;
unsigned long long Directory;
unsigned long long Block_special;
unsigned long long Symbolic_link;
unsigned long long Socket;
unsigned long long Whiteout;
unsigned long long Unknown;
// File error counts
unsigned long long Null_pathname;
unsigned long long Total_files;
unsigned long long Empty;
unsigned long long Perm_denied;
unsigned long long Stat_fails;
unsigned long long Open_fails;

unsigned long long SHA1_fails;
unsigned long long SHA256_fails;
unsigned long long Missing_tag;

unsigned long long Total_bytes;     // Size of all files scanned
unsigned long long Files_checked; // Files actually scanned in first pass
unsigned long long Files_hashed;
unsigned long long Bytes_hashed;
unsigned long long Files_checked; // Files actually scanned in first pass


uid_t User_id;
gid_t Group_id;

char const *Program_name; // Points to argv[0], for benefit of subroutines generating error messages

void sig_handler(int);
void alarm_handler(int sig);
int update_reg_file(const char *,const struct stat *);
int verify_reg_file(const char *,const struct stat *);
void print_stats(void);

// Our function that will handle each file in the hierarchy
int process_file(char const *pathname,struct stat const *statbuf,int typeflag,struct FTW *ftwbuf);

int Verbose;
int Quiet;

int main(int argc,char *argv[]){
  char const *locale_string = "en_US.UTF-8";

  Program_name = argv[0];
  User_id = geteuid();
  Group_id = getegid();
  umask(0);
  int nftw_flags = FTW_PHYS|FTW_ACTIONRETVAL;

  if(sha256_selftest() != 0)
    exit(1);
  if(sha1_selftest() != 0)
    exit(1);

  /* Process command line args */
  int c;
  while((c = getopt(argc,argv,"vcL:0qx")) != EOF){
    switch(c){
    case 'q':
      Quiet++;
      break;
    case 'x':
      nftw_flags |= FTW_MOUNT; // Don't cross mount points
      break;
    case 'v':
      Verbose++;
      break;
    case 'c':
      Check_tags++; // Verify correctness of all existing, up-to-date tags
      break;
    case 'L':
      locale_string = optarg;
      break;
    case '0':
      Zero_flag++; /* Path names are delimited by nulls, e.g., from 'find . -print0' */
      break;
    default:
      printf("Usage: %s [-v] [-0] [-q] [-c] [-x] [-L locale]",Program_name);
      break;
    }
  }

  if(Check_tags && Verbose)
    printf("Verifying hash tags, this can take some time\n");
  if(NULL == setlocale(LC_NUMERIC,locale_string))
    printf("setlocale %s failed\n",locale_string);


  // Catch signals so we can show statistics if the user hits ^C
  {
#if __APPLE__
  signal(SIGHUP,sig_handler);
  signal(SIGINT,sig_handler);
  signal(SIGQUIT,sig_handler);
  signal(SIGILL,sig_handler);
  signal(SIGABRT,sig_handler);
  signal(SIGBUS,sig_handler);
  signal(SIGSEGV,sig_handler);
  signal(SIGSYS,sig_handler);
  signal(SIGPIPE,sig_handler);
  signal(SIGALRM,sig_handler);
  signal(SIGTERM,sig_handler);
  signal(SIGXCPU,sig_handler);
  signal(SIGXFSZ,sig_handler);
  signal(SIGVTALRM,sig_handler);
  signal(SIGPROF,sig_handler);
  signal(SIGUSR1,sig_handler);
  signal(SIGUSR2,sig_handler);
#else

  struct sigaction act;
  void action(int,siginfo_t *,void *);
  
  //  act.sa_mask = NULL;
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = action;
  sigaction(SIGHUP,&act,NULL);
  sigaction(SIGINT,&act,NULL);
  sigaction(SIGQUIT,&act,NULL);
  sigaction(SIGILL,&act,NULL);
  sigaction(SIGABRT,&act,NULL);
  sigaction(SIGBUS,&act,NULL);
  sigaction(SIGSEGV,&act,NULL);
  sigaction(SIGSYS,&act,NULL);
  sigaction(SIGPIPE,&act,NULL);
  sigaction(SIGALRM,&act,NULL);
  sigaction(SIGTERM,&act,NULL);
  sigaction(SIGXCPU,&act,NULL);
  sigaction(SIGXFSZ,&act,NULL);
  sigaction(SIGVTALRM,&act,NULL);
  sigaction(SIGPROF,&act,NULL);
  sigaction(SIGUSR1,&act,NULL);
  sigaction(SIGUSR2,&act,NULL);
#endif
  }
  // Process files and directories given as command-line arguments
  // Dereference symbolic links only here, not in subdirectories
  if(optind < argc){
    for(int i=optind;i<argc;i++){
      struct stat statbuf;

      if(strlen(argv[i]) >= PATH_MAX)
	continue;
      
      if(lstat(argv[i],&statbuf) == -1){
	if(errno == EPERM)
	  Perm_denied++;
	printf("main: can't stat(%s): %s\n",argv[i],strerror(errno));
      } else if((statbuf.st_mode & S_IFMT) == S_IFLNK){
	// Dereference symbolic link
	char link_target[PATH_MAX];
	int linklen;
	if((linklen = readlink(argv[i],link_target,sizeof(link_target))) == -1){
	  if(errno == EPERM)
	    Perm_denied++;
	  printf("can't readlink(%s): %s\n",link_target,strerror(errno));
	} else {
	  if(linklen < sizeof(link_target))
	    link_target[linklen] = '\0';
	  if(stat(link_target,&statbuf) == -1){
	    printf("link target stat(%s) failed: %s\n",link_target,strerror(errno));
	  } else if((statbuf.st_mode & S_IFMT) == S_IFREG){
	    process_file(link_target,&statbuf,FTW_F,NULL);
	  } else if((statbuf.st_mode & S_IFDIR) == S_IFDIR){
	    int r;
	    if((r = nftw(link_target,process_file,Nopenfd,nftw_flags)) != 0){
	      printf("ntfw(%s) returns %d\n",argv[i],r);
	    }	    
	  }
	}
      } else if((statbuf.st_mode & S_IFMT) == S_IFREG){
	process_file(argv[i],&statbuf,FTW_F,NULL);
      } else if((statbuf.st_mode & S_IFDIR) == S_IFDIR){
	int const r = nftw(argv[i],process_file,Nopenfd,nftw_flags);
	if(r != 0)
	  printf("ntfw(%s) returns %d\n",argv[i],r);
      } else
	printf("%s is not symlink, directory or regular file\n",argv[i]);
    }
  } else {
    //else optind >= argc
    // If no command line args, read lines from stdin
    if(Verbose)
      printf("Reading file names from standard input...\n");
    while(!feof(stdin)){
      int ll;
      char pathname[PATH_MAX];
      
      for(ll=0; ll<PATH_MAX; ll++){
	char ch = getc(stdin);
	// Translate EOF or newline to terminal null
	if(ch == EOF || (!Zero_flag && '\n' == ch))
	  ch = '\0';
	
	pathname[ll] = ch;
	if(ch == '\0')
	  break;
      }
      if(ll == PATH_MAX){
	// Input line was too long; flush until terminating null/newline/EOF
	printf("Input line > PATH_MAX (%d); flushing\n",PATH_MAX);
	char ch;
	do {
	  ch = getc(stdin);
	  // Translate EOF or newline to terminating null
	} while(ch != '\0' && ch != EOF && (!Zero_flag && '\n' != ch));
      } else if(ll > 0){	    // Ignore empty lines
	struct stat statbuf;
	int typeflag = FTW_NS;
	if(lstat(pathname,&statbuf) == 0){
	  switch(statbuf.st_mode & S_IFMT){
	  case S_IFREG:
	    typeflag = FTW_F;
	    break;
	  case S_IFDIR:
	    typeflag = FTW_D;
	    break;
	  case S_IFLNK:
	    typeflag = FTW_SL;
	    break;
	  }
	} else {
	  printf("main: lstat(%s) failed, %s\n",pathname,strerror(errno));
	}// if(lstat
	process_file(pathname,&statbuf,typeflag,NULL);
      } // ll > 0
    } // while(!feof
  }
  if(Verbose || !Quiet)
    print_stats();
  exit(0);
}


// Process a path name
// Return codes:
//  0: normal
int process_file(char const *pathname,struct stat const *statbuf,int typeflag,struct FTW *ftwbuf){
  Total_files++;
  int retval = FTW_CONTINUE;

  /* Ignore null path names */
  if(pathname == NULL || strlen(pathname) == 0){
    Null_pathname++;
    if(Verbose > 1)
      printf("null pathname\n");
    goto done;
  }
  if(statbuf == NULL || typeflag == FTW_NS){
    Stat_fails++;
    printf("process_file stat(%s) failed: %s\n",pathname,strerror(errno));
    goto done; // Stat() failed, no analysis possible
  }
  // Count file types
  switch(statbuf->st_mode & S_IFMT){
  case S_IFIFO:
    FIFO++;
    if(Verbose > 1)
      printf("%s FIFO\n",pathname);
    break;
  case S_IFBLK:
    Block_special++;;
    if(Verbose > 1)
      printf("%s block special\n",pathname);
    break;
  case S_IFCHR:
    Character_special++;
    if(Verbose > 1)
      printf("%s char special\n",pathname);
    break;
  case S_IFSOCK:
    Socket++;
    if(Verbose > 1)
      printf("%s socket\n",pathname);
    break;
#ifdef S_IFWHT
  case S_IFWHT:
    Whiteout++;
    if(Verbose > 1)
      printf("%s whiteout\n",pathname);
    break;
#endif
  case S_IFLNK:
    if(Verbose > 1)
      printf("%s symbolic link\n",pathname);
    Symbolic_link++;
    break;
  case S_IFDIR:
    Directory++;
    if(Verbose > 1)
      printf("%s directory\n",pathname);
    break;
  default:
    Unknown++;
    if(Verbose > 1)
      printf("%s unknown type 0%o\n",pathname,statbuf->st_mode & S_IFMT);
    break;
  case S_IFREG:
    Regular_files++;
    // Process only regular files; symbolic links could be tagged but is that useful?
    if(statbuf->st_blocks == 0 || statbuf->st_size == 0){
      // Ignore empty files and files with no assigned data blocks (any data being stored in the inode).
      if(Verbose > 1)
	printf("%s empty regular file\n",pathname);
      Empty++;
      break;
    }
    Files_checked++;
    Total_bytes += statbuf->st_size;

    // Maintaining an open file descriptor is probably more efficient than invoking multiple system calls with the same path name 
    // Note that you can change the external tags of a file open read-only, but you need
    // write permission on the file itself.
    // The O_NOATIME flag is restricted to root or the owner of the file
    int flags = O_RDONLY;
    if(User_id == 0 || User_id == statbuf->st_uid)
      flags |= O_NOATIME;

    int const fd = open(pathname,flags);
    if(fd == -1){
      if(errno == EPERM || errno == EACCES)
	Perm_denied++;
      Open_fails++;
      if(Verbose){
	printf("Can't read %s: %s\n",pathname,strerror(errno));
      }
    } else if(Check_tags){
      int const r = verify_tag_fd(fd,statbuf);
      if(r == -1){
	if(Verbose)
	  printf("%s: verify_tag_fd error; %s\n",pathname,strerror(errno));
      } else {
	if(r & SHA1_MISMATCH){
	  SHA1_fails++;
	  printf("SHA1 mismatch: %s\n",pathname);
	}
	if(r & SHA256_MISMATCH){
	  SHA256_fails++;
	  printf("SHA256 mismatch: %s\n",pathname);      
	}
	if(r & MISSING_TAGS){
	  Missing_tag++;
	}
      }
    } else {
      if(flock(fd,LOCK_EX|LOCK_NB) == -1){
	if(Verbose > 1)
	  printf("Skipping %s\n",pathname);
      } else {
	long long const r = update_tag_fd(fd,statbuf);
	flock(fd,LOCK_UN);
	if(Verbose && r > 0)
	  printf("Updated %s\n",pathname);
	if(r == -1){
	  printf("%s: update_tag_fd error; %s\n",pathname,strerror(errno));
	} else if(r > 0){
	  Bytes_hashed += r;
	  Files_hashed++;
	}
      }
    }
    if(fd != -1)
      close(fd);
    break;
  }
 done:;
  return retval;
}

#if __APPLE__
void sig_handler(int sig){
  if(Verbose)
    printf("%s: Signal %d (%s) caught\n",Program_name,sig,strsignal(sig));
  print_stats();
  exit(1);
}
#else
void action(int sig,siginfo_t *siginfo, void *p){
  if(Verbose)
    printf("%s: Signal %d (%s) caught\n",Program_name,sig,strsignal(sig));
  psiginfo(siginfo,"signal caught");
  print_stats();
  exit(1);
}
#endif

void print_stats(void){
  if(Total_files)
    printf("Total files: %'llu\n",Total_files);
  if(Stat_fails)
    printf("Stat() failed: %'llu\n",Stat_fails);
  if(FIFO)
    printf("FIFOs: %'llu\n",FIFO);
  if(Character_special)
    printf("Character special: %'llu\n",Character_special);
  if(Directory)
    printf("Directories: %'llu\n",Directory);
  if(Block_special)
    printf("Block special: %'llu\n",Block_special);
  if(Symbolic_link)
    printf("Symbolic link: %'llu\n",Symbolic_link);
  if(Socket)
    printf("Socket: %'llu\n",Socket);
  if(Whiteout)
    printf("Whiteout: %'llu\n",Whiteout);
  if(Unknown)
    printf("Unknown: %'llu\n",Unknown);

  if(Regular_files)
    printf("Regular files: %'llu\n",Regular_files);

  if(Null_pathname)
    printf("Null pathnames: %'llu\n",Null_pathname);
  if(Empty)
    printf("Empty: %'llu\n",Empty);
  if(Perm_denied)
    printf("Permission denied: %'llu\n",Perm_denied);
  if(Open_fails)
    printf("Open failed: %'llu\n",Open_fails);

  printf("Non-empty files examined: %'llu\n",Files_checked);
  printf("Total bytes: %'llu\n",Total_bytes);
  if(Missing_tag)
    printf("Missing/stale tags: %'llu\n",Missing_tag);
  if(Bytes_hashed)
    printf("Bytes hashed: %'llu\n",Bytes_hashed);

  if(Check_tags){
    printf("SHA1 compare failures: %'llu\n",SHA1_fails);
    printf("SHA256 compare failures: %'llu\n",SHA256_fails);  
  } else {
    printf("Files updated: %'llu\n",Files_hashed);
  }
}

