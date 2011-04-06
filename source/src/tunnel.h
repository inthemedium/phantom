#ifndef __HAVE_TUNNEL_H__
#define __HAVE_TUNNEL_H__

/*2 ip v6 adresses in binary form + 2 x 32 bit (rest is padding for blocksize) */
/* or SHA_DIGEST_LENGTH + 1 ipv6 adress in binary form */
#define TUNNEL_BLOCK_SIZE 48

#include "server.h"
#include "path.h"

struct tunnel_dummy_package {
	struct tunnel_dummy_package *next;
	struct tunnel_dummy_package *prev;
	uint8_t key[SYMMETRIC_CIPHER_KEY_LEN];
	uint8_t iv[SYMMETRIC_CIPHER_IV_LEN];
	uint8_t package[TUNNEL_BLOCK_SIZE];
	uint8_t original_dummy[TUNNEL_BLOCK_SIZE];
};

struct tunnel {
	int nkeys;
	int is_entry_tunnel;
	pthread_t tid;
	int quit;
	EVP_CIPHER_CTX *ectxs;
	EVP_CIPHER_CTX *dctxs;
	struct ssl_connection *conn;
};

struct tunnel *create_tunnel(struct in6_addr *ap, const struct path *path);
struct tunnel *await_entry_tunnel(const struct in6_addr *own_ap, struct in6_addr *remote_ip, const struct path *path, const struct config *config);
int tunnel_read(struct tunnel *t, uint8_t *buf, int num);
int tunnel_write(struct tunnel *t, const uint8_t *buf, int num);
void free_tunnel(struct tunnel *t);

/* needed by server */
struct tunnel *create_ap_reservation_tunnel(const struct path *path);
struct tunnel_dummy_package *create_tunnel_dummy_package(const uint8_t *received, const struct conn_ctx *conn);
uint8_t *decrypt_tunnel_block(const struct tunnel_dummy_package *dp, const uint8_t *data);
int extract_exit_init_reply_package(const uint8_t *received, struct in6_addr *ap);
int extract_entry_init_reply_package(const uint8_t *received, uint32_t *flags);

#endif
