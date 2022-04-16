// $Id: file_monitor.c,v 1.6 2021/09/28 06:01:23 karn Exp $
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <getopt.h>
#include <string.h>
#include <sys/fanotify.h>
#include <errno.h>
#include <time.h>
#include "filehash.h"

int Verbose;
FILE *Logfile;

int main(int argc,char *argv[]){
  int c;
  char *logfile = NULL;
  while((c = getopt(argc,argv,"vl:")) != -1){
    switch(c){
    case 'l':
      logfile = optarg;
      break;
    case 'v':
      Verbose++;
      break;
    default:;
      break;
    }
  }
  if(argc < optind){
    printf("Usage: %s filesystem\n",argv[0]);
    exit(1);
  }

  char filesystem[PATH_MAX];
  int n = snprintf(filesystem,sizeof(filesystem)-1,"/%s",argv[optind]);
  filesystem[n] = '\0';
  if(logfile){
    char tmp[PATH_MAX];
    snprintf(tmp,sizeof(tmp)-1,"%s/%s.log",logfile,argv[optind]);
    Logfile = fopen(tmp,"a");
    if(Logfile)
      setlinebuf(Logfile);
    else
      printf("Log file create %s failed: %s\n",tmp,strerror(errno));
  }
  printf("Monitoring %s\n",filesystem);

  int fd = fanotify_init(FAN_CLASS_CONTENT|FAN_UNLIMITED_QUEUE,O_RDONLY);
  if(fd == -1){
    perror("fanotify_init");
    exit(1);
  }
  //  int r = fanotify_mark(fd,FAN_MARK_ADD|FAN_MARK_FILESYSTEM,FAN_MODIFY,0,filesystem);
  // Only examine the file when it's closed for write. We'll see if it has changed
  int r = fanotify_mark(fd,FAN_MARK_ADD|FAN_MARK_FILESYSTEM,FAN_CLOSE_WRITE,0,filesystem);
  if(r == -1){
    perror("fanotify_mark");
    exit(1);
  }
  char buffer[8192];
  int len;
  while((len = read(fd,buffer,sizeof(buffer))) > 0){
    struct fanotify_event_metadata *fp;
    fp = (struct fanotify_event_metadata *)buffer;
    while(FAN_EVENT_OK(fp,len)){
      if(fp->vers != FANOTIFY_METADATA_VERSION){
	printf("Unexpected version number %d\n",fp->vers);
	exit(1);
      }
      struct stat statbuf;
      if(fstat(fp->fd,&statbuf) == -1){
	if(Verbose)
	  printf("Can't fstat %d: %s\n",fp->fd,strerror(errno));
	if(Logfile)
	  fprintf(Logfile,"Can't fstat %d: %s\n",fp->fd,strerror(errno));	  
	goto next;
      }
      if(statbuf.st_nlink < 1){
	if(Verbose > 1)
	  printf("Skipping unlinked fd %d\n",fp->fd);
	if(Logfile)
	  fprintf(Logfile,"Skipping unlinked fd %d\n",fp->fd);	  
	goto next;
      }
      // Good, process
      if(Verbose || Logfile){
	time_t t;
	struct tm *tmc;
	time(&t);
	tmc = gmtime(&t);

	char tmp[PATH_MAX];
	snprintf(tmp,sizeof(tmp)-1,"/proc/self/fd/%d",fp->fd);
	char fname[PATH_MAX];
	int l = readlink(tmp,fname,sizeof(fname)-1);
	fname[l] = 0;
	if(Verbose)
	  printf("%04d-%02d-%02dT%02d:%02d:%02dZ size %llu pid %d %s\n",
		 tmc->tm_year+1900,tmc->tm_mon+1,tmc->tm_mday,tmc->tm_hour,tmc->tm_min,tmc->tm_sec,
		 (long long unsigned)statbuf.st_size,fp->pid,fname);

	if(Logfile){
	  fprintf(Logfile,"%04d-%02d-%02dT%02d:%02d:%02dZ size %llu pid %d %s\n",
		  tmc->tm_year+1900,tmc->tm_mon+1,tmc->tm_mday,tmc->tm_hour,tmc->tm_min,tmc->tm_sec,
		  (long long unsigned)statbuf.st_size,fp->pid,fname);
	}
      }
      fdatasync(fp->fd);
      update_tag_fd(fp->fd,&statbuf);
    next:;
      close(fp->fd);
      fp = FAN_EVENT_NEXT(fp,len);
    }
  }
  printf("read returned %d\n",len);
  exit(0);
}
