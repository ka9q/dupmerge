.DEFAULT_GOAL := all

BUILD ?= release
ENABLE_ALL    ?= 1
prefix        ?= /usr/local
exec_prefix   ?= $(prefix)
bindir        ?= $(exec_prefix)/bin
sbindir       ?= $(exec_prefix)/sbin
libdir        ?= $(exec_prefix)/lib
datadir       ?= $(prefix)/share
localstatedir ?= /var

UNAME_S := $(shell uname -s)

CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?=

ifeq ($(UNAME_S),Darwin)
  CPPFLAGS += -I/opt/local/include
  LDFLAGS  += -L/opt/local/lib
else
  LDLIBS += -lbsd
endif

ifeq ($(BUILD),debug)
     DOPTS = -g
else
     DOPTS = -DNDEBUG=1 -O3
endif

ifdef SANITIZE
     DOPTS += -fsanitize=address -fsanitize=undefined
     LDOPTS = -fsanitize=address -fsanitize=undefined
endif

ARCHOPTS = -march=native
# do NOT set -ffast-math or -ffinite-math-only; NANs are widely used as 'variable not set' sentinels
COPTS = -std=gnu11 -Wall -Wextra -MMD -MP
COPTS += -fPIC
CFLAGS += $(DOPTS) $(ARCHOPTS) $(COPTS) $(INCLUDES)

CC=gcc

# file_monitor not supported on MacOS - uses Linux specific fanotify(7) facility
#APPS= dupmerge checkattr pathnames mergefiles construct rmdups
APPS= checkattr dupmerge

all:  $(APPS)

rmdups: rmdups.o
	$(CC) $(CFLAGS) -o rmdups rmdups.o

construct: construct.o library.o
	$(CC) $(CFLAGS) -o construct construct.o library.o -lcrypto

mergefiles: mergefiles.o
	$(CC) $(CFLAGS) -o mergefiles mergefiles.o

checkattr: checkattr.o library.o
	$(CC) $(CFLAGS) -o checkattr checkattr.o library.o -lcrypto -lz

dupmerge: dupmerge.o library.o
	$(CC) $(CFLAGS) -o dupmerge dupmerge.o library.o -lcrypto -lz

checkattr.o: checkattr.c filehash.h

library.o: library.c filehash.h

install: $(APPS)
	install -b -m 0755 -S -v $^ $(DESDIR)$(bindir)

clean:
	rm -f *.o *.a $(APPS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $< 
