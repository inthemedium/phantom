include protobufobjects
OBJECTS=helper.o netdb.o path.o x509_flat.o config.o server.o conn_ctx.o logger.o openssl_locking.o rc4rand.o tunnel.o kademlia.o diskcache.o kademlia_rpc.o kad_contacts.o main.o thread_pool.o tun.o drop_privs.o addr.o measure.o
OBJECTSD=phantomd.o
CC=gcc
#CC=clang
CFLAGS=-O0 -g -ansi -pipe -D_POSIX_C_SOURCE=200112L -I/usr/include/libxml2 -Wall -Werror -Wextra -Wbad-function-cast -Wcast-qual -Wdeclaration-after-statement -Wmissing-prototypes -Wpointer-arith -Wshadow -Wstrict-prototypes -Wformat -Wformat-security -Wunused -Wwrite-strings -Waggregate-return -pedantic #-Wuninitialized -fstack-protector-all
LIBS=-lcrypto -lssl -lxml2 -lrt -lpthread -lprotobuf-c
#LIBS=-lcrypto -lssl -lxml2 -lrt -lpthread -lprotobuf-c -I../lssl/openssl-1.0.0 L../lssl/openssl-1.0.0
BINARY=phantom
BINARYD=phantomd

all: $(BINARY) $(BINARYD)

$(BINARYD): $(OBJECTSD)
	$(CC) -o $(BINARYD) $(OBJECTSD) $(CFLAGS)

$(BINARY): $(OBJECTS) $(PROTOOBJECTS)
	$(CC) -o $(BINARY) $(OBJECTS) $(PROTOOBJECTS) $(CFLAGS) $(LIBS)

indent:
	#modeled after /usr/src/linux/scripts/Lindent
	SIMPLE_BACKUP_SUFFIX=.b4indent indent -kr -i8 -ts8 -sob -l80 -ss -bs -psl -cli8 *.c

clean:
	rm -f $(OBJECTS) $(PROTOOBJECTS) $(BINARY) $(BINARYD) $(OBJECTSD) *.c.b4indent *.log *.plist

efence: $(OBJECTS) $(PROTOOBJECTS)
	$(CC) -o $(BINARY) $(OBJECTS) $(PROTOOBJECTS) $(CFLAGS) $(LIBS) -lefence

tags:
	ctags -R

analyze:
	for i in $(OBJECTS) $(OBJECTSD); do j=`basename $$i .o`; echo "Checking $$j..."; clang --analyze $(CFLAGS) $$j.c; rm -f $$j.plist; done

.PHONY: clean indent efence analyze tags
