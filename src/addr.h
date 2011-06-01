#ifndef __HAVE_ADDR_H__
#define __HAVE_ADDR_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>

/*NETMASK=fd00:2522:3493:ffff:ffff:*/
#define AP_PREFIX {0xfd, 0x00, 0x25, 0x22, 0x34, 0x93, 0xff, 0xff, 0xff, 0xff}
#define DEVICE_NAME "phantom"
#define SOCKNAME "/tmp/phantom"

int set_addr(struct in6_addr *addr);
int del_addr(struct in6_addr *addr);

#endif
