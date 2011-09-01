#ifndef __HAVE_KADEMLIA_H__
#define __HAVE_KADEMLIA_H__

#include <inttypes.h>
#include <semaphore.h>
#include "config.h"
#include "list.h"
#include "diskcache.h"
#include "cleanup_stack.h"
#include "x509_flat.h"
#include "kademlia.pb-c.h"
#include "setuppackage.pb-c.h"
#include "netdb.h"
#include "addr.h"

#define NBUCKETS (SHA_DIGEST_LENGTH * 8)
#define CHECKQUITTIMEOUT 5
#define KADEMLIA_K 20
#define KADEMLIA_ALPHA 3
#define PING_TIMEOUT 10
#define HOUSE_KEEPING_TIMEOUT 30
#define TIME_SPEED_FACTOR 1/1800
#define KAD_T_REFRESH 30 /* bucket refresh */
#define KAD_T_REPLICATE 2 /* publish entire db */
#define KAD_T_REPUBLISH 30 /* republish own key/value pairs */
#define KAD_T_EXPIRE (KAD_T_REPUBLISH + 60) /* key value ttl */

#define MAX_JOIN_RETRIES 5
#define JOIN_WAIT 5

struct kad_metadata {
	uint8_t key[SHA_DIGEST_LENGTH];
	struct timespec exp_time;
	uint32_t version;
};

struct keys {
	struct keys *next;
	struct keys *prev;
	uint8_t key[SHA_DIGEST_LENGTH];
};

struct thread {
	struct thread *next;
	struct thread *prev;
	pthread_t thread;
};

struct kad_node_info {
	struct kad_node_info *prev;
	struct kad_node_info *next;
	uint8_t id[SHA_DIGEST_LENGTH];
	X509 *cert;
	X509 *pbc;
	uint16_t port;
	struct timespec last_seen;
	char *ip;
	int ponged;
	sem_t sem;
};

struct kad_table {
	struct kad_node_info buckets[NBUCKETS];
	int entries[NBUCKETS];
	struct timespec last_action[NBUCKETS];
	pthread_mutex_t bucket_mutexes[NBUCKETS];
};

struct ping_nodes {
	struct kad_node_info list;
	pthread_mutex_t lock;
	sem_t sem;
};

struct updates {
	struct kad_node_info list;
	pthread_mutex_t mutex;
	sem_t sem;
};

struct kad_node_list {
	struct kad_node_info list;
	int nentries;
};

struct kad {
	struct kad_table *table;
	struct ping_nodes *ping;
	struct disk_cache *cache;
	const struct config *config;
	uint8_t own_id[SHA_DIGEST_LENGTH];
	struct updates updates;
	int quit;
	NodeInfo self;
	struct thread thread_list;
	char *nodefile;
	struct timespec last_replication;

	/* there might be a better place to store this node's RTE */
	RoutingTableEntry *rte;
	struct timespec last_republication;
};

/* interface functions for kademlia */
int start_kad(const struct config *config);
void stop_kad(void);
int kad_store(uint8_t *key, uint8_t *data, uint32_t len);
int kad_find(uint8_t *key, uint8_t **data, size_t *len);
struct kad_node_list *get_n_nodes_debug(int n);
struct kad_node_list *get_n_nodes(int n);

/* Functions needed from other kademlia modules */
int local_find(const uint8_t *key, uint8_t **data, size_t *len);
int local_store(struct kad_metadata *metadata, const uint8_t *data, uint32_t len);
struct kad_node_list *get_k_closest_nodes(const uint8_t *id, const uint8_t *requestor);
void free_kad_node_list(struct kad_node_list *l);
struct kad_node_info *new_kad_node_info(const uint8_t *id, const char *ip, uint16_t port, X509 *cert, X509 *pbc);
void free_kad_node_info(struct kad_node_info *n);
void update_table_relay(const struct kad_node_info *n);
void update_kad_publishing(RoutingTableEntry *rte);
#endif
