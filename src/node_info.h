#ifndef __HAVE_NODE_INFO_H__
#define __HAVE_NODE_INFO_H__

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include "x509_flat.h"

struct node_info {
	X509 *construction_certificate; /* path building certificate */
	struct X509_flat *construction_certificate_flat;
	X509 *communication_certificate; /* communication certificate */
	struct X509_flat *communication_certificate_flat;
	char *ip;
	uint16_t port;
	uint32_t flags;
};

#define X_NODE (0x01)
#define Y_NODE (0x02)
#define T_NODE (0x04)
#define ENTRY_NODE (0x08)
#define SUCCESS_FLAG (0x10)
#define RESERVE_AP (0x20)

#endif
