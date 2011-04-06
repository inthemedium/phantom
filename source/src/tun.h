#ifndef __HAVE_TUN_H__
#define __HAVE_TUN_H__

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include "tunnel.h"
#include "helper.h"

#define MAX_MTU_SIZE 1500


struct ap_to_tun {
	struct ap_to_tun *prev;
	struct ap_to_tun *next;
	struct in6_addr ap;
	struct tunnel *tun;
};

struct tun_dev {
	int fd;
	int quit;
	int has_awaiter;
	const struct config *config;
	pthread_t reader;
	pthread_t awaiter;
	char name[IFNAMSIZ];
	pthread_mutex_t map_mutex;
	struct ap_to_tun map;
	pthread_mutex_t write_lock;
};

struct tun_dev *start_forwarding(struct path *path, const struct config *config);
void stop_forwarding(struct tun_dev *t);

#endif
