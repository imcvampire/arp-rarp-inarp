
CC = gcc
CFLAGS = -Wall -Wextra -Werror
INSTALL = install
prefix = /usr/local
sbindir = ${prefix}/sbin

all: inarp

.PHONY: clean
clean:
	rm -f inarp

.PHONY: install
install: all
	$(INSTALL) -m 0755 -D inarp $(DESTDIR)$(sbindir)/inarp