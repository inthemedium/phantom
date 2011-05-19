#ifndef __HAVE_CONFIG_H__
#define __HAVE_CONFIG_H__

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "string.h"
#include "x509_flat.h"
#include "assert.h"
#include "helper.h"

/* all for aes_256_aes_cbc */
#define SYMMETRIC_CIPHER_KEY_LEN 64
#define SYMMETRIC_CIPHER_BLOCK_SIZE 16
#define SYMMETRIC_CIPHER_IV_LEN 16

#define RSA_KEY_LEN 2048
#define RSA_SIGN_LEN (RSA_KEY_LEN / 8)

struct config {
	char *ip;
	char *kad_node_file;
	char *kad_data_dir;
	uint16_t port;
	uint8_t nxnodes;
	uint8_t nynodes;
	uint8_t nkeys;
	X509 *construction_certificate;
	struct X509_flat *construction_certificate_flat;
	EVP_PKEY *private_construction_key;
	X509 *communication_certificate;
	struct X509_flat *communication_certificate_flat;
	EVP_PKEY *private_communication_key;
	X509 *routing_certificate;
	struct X509_flat *routing_certificate_flat;
	EVP_PKEY *private_routing_key;
};

void read_config(char *path, struct config *config);
void free_config(struct config *config);

#endif
