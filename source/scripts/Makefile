OBJECTS=tunnel.o
CC=gcc
CFLAGS=-O2 -ansi -pipe -D_POSIX_C_SOURCE=200112L -I/usr/include/libxml2 -Wall -Werror -Wextra -Wbad-function-cast -Wcast-align -Wcast-qual -Wdeclaration-after-statement -Wmissing-prototypes -Wpointer-arith -Wshadow -Wstrict-prototypes -Wformat -Wformat-security -Wunused -Wwrite-strings -Waggregate-return -pedantic #-Wuninitialized -fstack-protector-all
BINARY=tunnel

all: $(OBJECTS)
	$(CC) -o $(BINARY) $(OBJECTS) $(CFLAGS)

clean:
	rm -f $(OBJECTS) $(BINARY) *.c.b4indent *.log *.plist

.PHONY: clean
