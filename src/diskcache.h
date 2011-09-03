#ifndef __HAVE_DISK_CACHE_H__
#define __HAVE_DISK_CACHE_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include "config.h"
#include "list.h"
#include "kademlia.h"                   /* needed for metadata */

struct disk_record {
	struct disk_record *prev;
	struct disk_record *next;
	struct kad_metadata *metadata;
	int file;
	size_t file_len;
};

struct disk_cache {
	char *dirname;
	int len;
	pthread_mutex_t lock;
	struct disk_record files;
};

struct disk_cache *new_disk_cache(const char *dirname);
void free_disk_cache(struct disk_cache *d);
int disk_cache_store(struct disk_cache *d, struct kad_metadata *metadata, const uint8_t *data, uint32_t len);
uint8_t *disk_cache_find(struct disk_cache *d, const uint8_t *key, size_t *outsize);
void disk_cache_house_keeping(struct disk_cache *d);
int in_disk_cache(struct disk_cache *d, const struct kad_metadata *metadata);
#endif
