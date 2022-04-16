// mergefiles <source_directory> <destination_directory>

// Walk down source_directory, moving everything from source_directory into destination_directory that doesn't conflict
// If an ordinary file is already in place at the destination, compare it with the source. If they're identical, then simply unlink the source.
// If a directory is already in place at the destination, recursively scan the source directory and move as much as possible.
// Otherwise leave the source in place for manual reconciliation

// Warning: this is a potentially dangerous program, in that a bug (or misuse) could destroy a lot of files
// I have tried to check for every error condition and to take care with dangerous system calls like rename() and unlink()
// but be careful.
// October 2010, Phil Karn, KA9Q

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <locale.h>
#ifdef __linux__
#include <bsd/string.h>
#endif

#ifndef MAP_NOCACHE
#define MAP_NOCACHE (0)
#endif

char *Program_name;
char *Source_dirname;
char *Dest_dirname;

int Fast;
int Verbose;
int Dry_run;


int do_directory(char *);
char *filetype(int);
int files_different(char *,char *,off_t);

long long Files_renamed;
long long Directories_renamed;
long long Others_renamed;
long long Hardlinks;
long long Files_unlinked;
long long Errors;
long long Conflicts;

void usage(void){
    printf("Usage: %s [-f] [-v] [-n] [-L locale] <source directory> <destination directory>\n",Program_name);
}


int main(int argc,char *argv[]){
  struct stat source_statbuf,dest_statbuf,cwd_statbuf;
  char wd[PATH_MAX];
  int c;
  char *locale_string = "en_US.UTF-8";

  Program_name = argv[0];

  while((c = getopt(argc,argv,"fvL:n")) != EOF){
    switch(c){
    case 'f':
      Fast++;
      break;
    case 'v':
      Verbose++;
      break;
    case 'L':
      locale_string = optarg;
      break;
    case 'n':
      Dry_run++;
      break;
    default:
      usage();
      exit(1);
      break;
    }
  }

  if(optind + 2 != argc){
    usage();
    exit(1);
  }
  if(NULL == setlocale(LC_NUMERIC,locale_string))
     printf("setlocale %s failed\n",locale_string);

  if(Dry_run)
    printf("%s: Dry run; no files will actually be moved or unlinked\n",Program_name);


  Source_dirname = argv[optind];
  Dest_dirname = argv[optind+1];

  if(getcwd(wd,sizeof(wd)) == NULL){
    printf("%s: can't get current working directory: %s\n",Program_name,strerror(errno));
    exit(1);
  }
  if(lstat(wd,&cwd_statbuf) != 0){
    printf("%s: can't stat current working directory: %s\n",Program_name,strerror(errno));
    exit(1);
  }

  if(lstat(Source_dirname,&source_statbuf) != 0){
    printf("%s: stat on %s failed: %s\n",Program_name,Source_dirname,strerror(errno));
    exit(1);
  }
  if((source_statbuf.st_mode & S_IFMT) != S_IFDIR){
    printf("%s: %s is not a directory\n",Program_name,Source_dirname);
    exit(1);
  }
  if(cwd_statbuf.st_dev == source_statbuf.st_dev && cwd_statbuf.st_ino == source_statbuf.st_ino){
    // Source directory is current directory; make null
    Source_dirname = NULL;
  }
  if(lstat(Dest_dirname,&dest_statbuf) != 0){
    printf("%s: stat on %s failed: %s\n",Program_name,Dest_dirname,strerror(errno));
    exit(1);
  }
  if((dest_statbuf.st_mode & S_IFMT) != S_IFDIR){
    printf("%s: %s is not a directory\n",Program_name,Dest_dirname);
    exit(1);
  }
  if(cwd_statbuf.st_dev == dest_statbuf.st_dev && cwd_statbuf.st_ino == dest_statbuf.st_ino){
    // Destination directory is current directory; make null
    Dest_dirname = NULL;
  }
  if(source_statbuf.st_dev == dest_statbuf.st_dev && source_statbuf.st_ino == dest_statbuf.st_ino){
    printf("%s: Source and destination directories are the same\n",Program_name);
    exit(1);
  }

  do_directory(NULL); // Start walk at source directory
  printf("%s:",Program_name);
  if(Files_renamed)
    printf(" Files renamed: %'llu;",Files_renamed);
  if(Directories_renamed)
    printf(" Directories renamed: %'llu;",Directories_renamed);
  if(Others_renamed)
    printf(" Others renamed: %'llu;",Others_renamed);
  if(Hardlinks)
    printf(" Hardlinks unlinked: %'llu;",Hardlinks);
  if(Files_unlinked)
    printf(" Duplicate files unlinked: %'llu;",Files_unlinked);
  if(Errors)
    printf(" Errors: %'llu;",Errors);
  if(Conflicts)
    printf(" Conflicts: %'llu;",Conflicts);
  putchar('\n');

  exit(0);
}

// Process directory
// Argument is source entry relative to Source_dirname
// Argument will be NULL on initial entry, indicating that the source directory should be searched
int do_directory(char *pathname){
  DIR *dir;
  struct stat source_statbuf,target_statbuf;
  char source_directory_pathname[PATH_MAX];
  char source_pathname[PATH_MAX];
  char target_pathname[PATH_MAX];

  printf("do_directory(%s)\n",pathname);
  source_directory_pathname[0] = '\0';
  if(Source_dirname != NULL){
    strlcat(source_directory_pathname,Source_dirname,sizeof(source_directory_pathname));
    strlcat(source_directory_pathname,"/",sizeof(source_directory_pathname));
  }
  if(pathname != NULL){
    strlcat(source_directory_pathname,pathname,sizeof(source_directory_pathname));
    strlcat(source_directory_pathname,"/",sizeof(source_directory_pathname));
  }
  if(strlen(source_directory_pathname) == 0){
    // Default to reading current directory
    if((dir = opendir(".")) == NULL){
      printf("%s: Can't read current directory: %s\n",Program_name,strerror(errno));
      Errors++;
      return 0;
    }
  } else {
    if((dir = opendir(source_directory_pathname)) == NULL){
      printf("%s: Can't read source directory %s: %s\n",Program_name,source_directory_pathname,strerror(errno));
      Errors++;
      return 0;
    }
  }
  while(1){
    errno = 0;
    struct dirent *entry;
    entry = readdir(dir);
    if(entry == NULL){
      if(errno){
	printf("%s: read of directory %s failed: %s\n",Program_name,source_directory_pathname,strerror(errno));
	Errors++;
      }
      break; // End of directory
    }

    if(strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0)
      continue; // Ignore . and .. entries

    // Construct full path name of current source entry, and examine it
    source_pathname[0] = '\0';
    if(Source_dirname != NULL){
      strlcat(source_pathname,Source_dirname,sizeof(source_pathname));
      strlcat(source_pathname,"/",sizeof(source_pathname));
    }
    if(pathname != NULL){
      strlcat(source_pathname,pathname,sizeof(source_pathname));
      strlcat(source_pathname,"/",sizeof(source_pathname));
    }
    strlcat(source_pathname,entry->d_name,sizeof(source_pathname));
    if(lstat(source_pathname,&source_statbuf) != 0){
      printf("%s: Can't stat %s: %s\n",Program_name,source_pathname,strerror(errno));
      Errors++;
      continue; // ignore it
    }
    // Construct new target filename
    target_pathname[0] = '\0';
    if(Dest_dirname != NULL){
      strlcat(target_pathname,Dest_dirname,sizeof(target_pathname));
      strlcat(target_pathname,"/",sizeof(target_pathname));
    }
    if(pathname != NULL){
      strlcat(target_pathname,pathname,sizeof(target_pathname));
      strlcat(target_pathname,"/",sizeof(target_pathname));
    }      
    strlcat(target_pathname,entry->d_name,sizeof(target_pathname));
    // See if target already exists
    if(lstat(target_pathname,&target_statbuf) != 0){
      if(errno == ENOENT){
	// Target does not exist; simply move original into place
	if((source_statbuf.st_mode & S_IFMT) == S_IFDIR)
	  Directories_renamed++;
	else if((source_statbuf.st_mode & S_IFMT) == S_IFREG)
	  Files_renamed++;
	else
	  Others_renamed++;
	printf("rename(%s,%s)\n",source_pathname,target_pathname);
	if(!Dry_run){
	  if(rename(source_pathname,target_pathname) != 0){
	    printf("%s: rename(%s,%s) failed: %s\n",Program_name,source_pathname,target_pathname,strerror(errno));
	    Errors++;
	  }
	}
      } else {
	// target stat failed for a reason other than it didn't exist
	printf("%s: stat(%s) failed: %s\n",Program_name,target_pathname,strerror(errno));
	Errors++;
      }
    } else if((source_statbuf.st_mode & S_IFMT) != (target_statbuf.st_mode & S_IFMT)){
      // Target exists, but is not of same type as source
      printf("%s: %s is a %s but %s is a %s\n",Program_name,source_pathname,filetype(source_statbuf.st_mode),
	      target_pathname,filetype(target_statbuf.st_mode));
      Conflicts++;
    } else if((source_statbuf.st_mode & S_IFMT) == S_IFDIR){
      // target directory already exists; call ourselves recursively to copy as much as we can
      // Reconstruct source pathname to be pathname/entry->dname, i.e., minus source directory
      source_pathname[0] = '\0';
      if(pathname != NULL){
	strlcat(source_pathname,pathname,sizeof(source_pathname));
	strlcat(source_pathname,"/",sizeof(source_pathname));
      }
      strlcat(source_pathname,entry->d_name,sizeof(source_pathname));

      do_directory(source_pathname);
    } else if((source_statbuf.st_mode & S_IFMT) == S_IFLNK){
      // Files are symbolic links, see if their contents match
      char source_buf[PATH_MAX];
      char target_buf[PATH_MAX];
      size_t s_len,t_len;

      s_len = readlink(source_pathname,source_buf,sizeof(source_buf));
      if(s_len == -1){
	printf("%s: Can't read symbolic link %s; %s\n",Program_name,source_pathname,strerror(errno));
      }
      t_len = readlink(target_pathname,target_buf,sizeof(target_buf));
      if(t_len == -1){
	printf("%s: Can't read symbolic link %s; %s\n",Program_name,target_pathname,strerror(errno));
      }
      if(s_len == t_len && memcmp(source_buf,target_buf,s_len) == 0){
	// Identical; unlink source
	Files_unlinked++;
	printf("duplicate link unlink(%s)\n",source_pathname);
	if(!Dry_run){
	  if(unlink(source_pathname) != 0){
	    printf("%s: unlink(%s) failed: %s\n",Program_name,source_pathname,strerror(errno));
	    Errors++;
	  }
	}
      } else {
	printf("%s: %s and %s are different\n",Program_name,source_pathname,target_pathname);
	Conflicts++;
      }
    } else if((source_statbuf.st_mode & S_IFMT) == S_IFREG){
      // source and target are both regular files. Are they already the same?
      if(source_statbuf.st_dev == target_statbuf.st_dev && source_statbuf.st_ino == target_statbuf.st_ino){
	// source and target are hardlinked; just unlink the source
	Hardlinks++;

	printf("hardlink unlink(%s)\n",source_pathname);
	if(!Dry_run){
	  if(unlink(source_pathname) != 0){
	    printf("%s: unlink(%s) failed: %s\n",Program_name,source_pathname,strerror(errno));
	    Errors++;
	  }
	}
      } else if(source_statbuf.st_size != target_statbuf.st_size){
	// source and target have different contents, leave both alone
	printf("%s: %s and %s have different sizes\n",Program_name,source_pathname,target_pathname);
	Conflicts++;
      } else if(!Fast && files_different(source_pathname,target_pathname,source_statbuf.st_size)){
	// source and target have different contents, leave both alone
	printf("%s: %s and %s are different\n",Program_name,source_pathname,target_pathname);
	Conflicts++;
      } else {
	// Files are the same, so we can safely delete the original
	// SHOULD PROBABLY COPY THE MODES AND OWNERS FIRST
	Files_unlinked++;
	printf("duplicate file unlink(%s)\n",source_pathname);
	if(!Dry_run){
	  if(unlink(source_pathname) != 0){
	    printf("%s: unlink(%s) failed: %s\n",Program_name,source_pathname,strerror(errno));
	    Errors++;
	  }
	}
      }
    } else {
      // Target already exists, is of same type as source, but isn't a directory or special file
      // I.e., is a special file. Should probably copy modes, then unlink source
      // For symbolic links, compare their targets
      // For now, leave both alone
    }
  }
  closedir(dir);
  return 0;
}

char *Filetypes[] = {
  "0",
  "FIFO",
  "character special",
  "3",
  "directory",
  "5",
  "block special",
  "7",
  "regular file",
  "o11",
  "symbolic link",
  "o13",
  "socket",
  "o15",
  "whiteout",
  "o17",
};

char *filetype(int x){
  return Filetypes[(x & S_IFMT) >> 12];
}

#define CHUNKSIZE (128*1024*1024)

int files_different(char *a,char *b,off_t filesize){
  int fda,fdb;
  char *ptr_a,*ptr_b;
  size_t chunk;
  off_t a_offset;
  off_t b_offset;
  int r = 0;

  if((fda = open(a,O_RDONLY)) == -1){
    printf("%s: Can't read %s: %s\n",Program_name,a,strerror(errno));
    Errors++;
    return -1;
  }
  if((fdb = open(b,O_RDONLY)) == -1){
    printf("%s: Can't read %s: %s\n",Program_name,b,strerror(errno));
    Errors++;
    close(fda);
    return -1;
  }
  a_offset = b_offset = 0;
  
  while(filesize > 0 && r == 0){
    // Compare 128MB at a time
    chunk = filesize > CHUNKSIZE ? CHUNKSIZE : filesize;
    ptr_a = mmap(NULL,chunk,PROT_READ,MAP_FILE|MAP_SHARED|MAP_NOCACHE,fda,a_offset);
    if(ptr_a == MAP_FAILED){
      printf("%s: mmap failed: %s\n",Program_name,strerror(errno));
      Errors++;
      r = -1;
      break;
    }
    ptr_b = mmap(NULL,chunk,PROT_READ,MAP_FILE|MAP_SHARED|MAP_NOCACHE,fdb,b_offset);
    if(ptr_b == MAP_FAILED){
      printf("%s: mmap failed: %s\n",Program_name,strerror(errno));      
      munmap(ptr_a,chunk);
      Errors++;
      r = -1;
      break;
    }
    if(memcmp(ptr_a,ptr_b,chunk) != 0){
      // File contents are different
      r = 1;
    }
    if(munmap(ptr_a,chunk) != 0){
      printf("%s: munmap failed: %s\n",Program_name,strerror(errno));
      Errors++;
      r = -1;
    }
    if(munmap(ptr_b,chunk) != 0){
      printf("%s: munmap failed: %s\n",Program_name,strerror(errno));
      Errors++;
      r = -1;
    }
    a_offset += chunk;
    b_offset += chunk;
    filesize -= chunk;
  }
  close(fda);
  close(fdb);
  return r;
 }
