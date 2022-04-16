CC=gcc
#CFLAGS=-g -O2 -Wall
CFLAGS=-g -Wall

#APPS= dupmerge checkattr pathnames mergefiles construct rmdups
APPS= checkattr dupmerge file_monitor mergefiles

all:  $(APPS)

rmdups: rmdups.o
	$(CC) $(CFLAGS) -o rmdups rmdups.o

construct: construct.o library.o
	$(CC) $(CFLAGS) -o construct construct.o library.o -l crypto

mergefiles: mergefiles.o
	$(CC) $(CFLAGS) -o mergefiles mergefiles.o -l bsd

checkattr: checkattr.o library.a
	$(CC) $(CFLAGS) -o checkattr checkattr.o library.a -lncurses -l crypto

dupmerge: dupmerge.o library.o
	$(CC) $(CFLAGS) -o dupmerge dupmerge.o library.o -l crypto

pathnames: pathnames.o
	$(CC) $(CFLAGS) -o pathnames pathnames.o

file_monitor: file_monitor.o library.a
	$(CC) $(CFLAGS) -o file_monitor file_monitor.o library.a -l crypto

library.a: library.o
	ar -rv library.a library.o

dupmerge.o: dupmerge.c filehash.h

checkattr.o: checkattr.c filehash.h

library.o: library.c filehash.h

file_monitor.o: file_monitor.c filehash.h

install: $(APPS)
	install -b -m 0755 -S -v $^ /usr/local/bin

clean:
	rm -f *.o *.a $(APPS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $< 
