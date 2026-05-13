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

CFILES = rmdups.c construct.c mergefiles.c copyfile.c dupmerge.c file_monitor.c library.c ogghash.c

CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?= -lcrypto -lz

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
APPS= dupmerge checkattr mergefiles construct rmdups

all:  $(APPS)

rmdups: rmdups.o
	$(CC) $(CFLAGS) -o $@ $^

construct: construct.o library.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

mergefiles: mergefiles.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

checkattr: checkattr.o ogghash.o library.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

dupmerge: dupmerge.o ogghash.o library.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

checkattr.o: checkattr.c filehash.h

library.o: library.c filehash.h

ogghash.o: ogghash.c filehash.h

install: $(APPS)
	install -b -m 0755 -S -v $^ $(DESDIR)$(bindir)

clean:
	rm -f *.o *.a *.d $(APPS)

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

DEPS = $(CFILES:.c=.d) $(OBJS:.o=.d)
-include $(DEPS)
