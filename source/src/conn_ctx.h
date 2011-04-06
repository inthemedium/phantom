#ifndef __HAVE_CONFIG_CTX_H__
#define __HAVE_CONFIG_CTX_H__

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <inttypes.h>
#include "config.h"
#include "helper.h"

struct xkeys {
	int nkeys;
	uint8_t *keys;
	uint8_t *ivs;
};

struct rte {
	uint32_t len;
	uint8_t *data;
};

struct conn_ctx {
	uint8_t prev_id[SHA_DIGEST_LENGTH];
	uint8_t next_id[SHA_DIGEST_LENGTH];
	char *prev_ip;
	char *next_ip;
	uint16_t prev_port;
	uint16_t next_port;
	uint32_t flags;
	uint8_t *peer_id; /* used for terminating nodes */
	char *peer_ip; /* used for terminating nodes */
	uint16_t peer_port; /* used for terminating nodes */
	X509 *peer_cert; /* used for terminating nodes */
	struct xkeys *keys;
	struct ssl_connection *to_next;
	X509 *prev_communication_certificate;
	X509 *next_communication_certificate;
	X509 *routing_certificate;
	RSA *construction_certificate;
	/* optional */
	struct in6_addr ap;
	struct rte rte;
};

struct conn_ctx *new_conn_ctx(void);
void free_conn_ctx(struct conn_ctx *conn);
#endif
