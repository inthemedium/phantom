#ifndef __HAVE_KADEMLIA_RPC_H__
#define __HAVE_KADEMLIA_RPC_H__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "kademlia.h"
#include "kademlia.pb-c.h"
#include "server.h"
#include "x509_flat.h"

#define FIND_TIMEOUT 20
#define STORE_TIMEOUT 20
#define KAD_MAGIC_STORE 0x22BE3DC6
#define KAD_MAGIC_FIND_VALUE 0xC2AE69D8
#define KAD_MAGIC_FIND_NODE 0xC4CE29E6

struct rpc_return {
	int success;
	int nnodes;
	struct kad_node_info *nodes[KADEMLIA_K];
	uint32_t len;
	uint8_t *data;
};

struct rpc_return *rpc_find_node(uint8_t *id, const struct kad_node_info *n, X509 *cert, EVP_PKEY *privkey, NodeInfo *self);
struct rpc_return *rpc_find_value(uint8_t *key, const struct kad_node_info *n, X509 *cert, EVP_PKEY *privkey, NodeInfo *self);
int rpc_store(uint8_t *key, uint8_t *data, uint32_t len, const struct kad_node_info *store_to, X509 *cert, EVP_PKEY *privkey, NodeInfo *self);
void free_rpc_return(struct rpc_return *r);

int handle_rpc_find_node(SSL *from, X509 *cert, uint8_t *package, int size);
int handle_rpc_find_value(SSL *from, X509 *cert, uint8_t *package, int size);
int handle_rpc_store(SSL *from, X509 *cert, uint8_t *package, int size);
#endif
