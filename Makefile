.DEFAULT_GOAL := all

BUILD ?= release
prefix        ?= /usr/local
exec_prefix   ?= $(prefix)
bindir        ?= $(exec_prefix)/bin
sbindir       ?= $(exec_prefix)/sbin
libdir        ?= $(exec_prefix)/lib
datadir       ?= $(prefix)/share
localstatedir ?= /var

UNAME_S := $(shell uname -s)

CFILES = mergefiles.c copyfile.c dupmerge.c file_monitor.c library.c ogghash.c

# file_monitor not supported on MacOS - uses Linux specific fanotify(7) facility
APPS= dupmerge checkattr mergefiles

CPPFLAGS ?=
LDFLAGS  ?=
LDLIBS   ?= -lcrypto

ifeq ($(UNAME_S),Darwin)
  CPPFLAGS += -I/opt/local/include
  LDFLAGS  += -L/opt/local/lib
else
  LDLIBS += -lbsd
  APPS += file_monitor
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

ifeq ($(TRACE),)
else
	DOPTS += -DTRACE=1
endif

ARCHOPTS =
COPTS = -std=gnu11 -Wall -Wextra -MMD -MP
CFLAGS += $(DOPTS) $(ARCHOPTS) $(COPTS) $(INCLUDES)

CC=gcc


all:  $(APPS)

rmdups: rmdups.o
	$(CC) -o $@ $^

construct: construct.o library.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

mergefiles: mergefiles.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

checkattr: checkattr.o ogghash.o library.o
	$(CC) -o $@ $^ $(LDFLAGS) -logg $(LDLIBS)

dupmerge: dupmerge.o ogghash.o library.o
	$(CC) -o $@ $^ $(LDFLAGS) -logg $(LDLIBS)

file_monitor: file_monitor.o library.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

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
