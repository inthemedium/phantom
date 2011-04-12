#ifndef __HAVE_HELPER_H__
#define __HAVE_HELPER_H__

#include <pthread.h>
#include <limits.h>
#include <stdlib.h>
#include <alloca.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>

struct ssl_connection {
	SSL *ssl;
	int socket;
	X509 *peer_cert;
};

void randomize_array(void *base, size_t nmemb, size_t size);
void reverse_array(void *base, size_t nmemb, size_t size);
X509 *read_x509_from_file(const char *path);
void hexdump(const void *buf, int size);
EVP_PKEY *rsa_to_pkey(RSA *rsa);
void serialize_32_t(uint32_t t, uint8_t *buf);
uint32_t deserialize_32_t(const uint8_t *buf);
void serialize_16_t(uint16_t t, uint8_t *buf);
uint16_t deserialize_16_t(const uint8_t *buf);
char *ip4_to_char(uint32_t ip);
struct ssl_connection *create_ssl_connection(const char *ip, uint16_t port, X509 *cert, EVP_PKEY *privkey);
struct ssl_connection *create_ssl_connection_tmout(const char *ip, uint16_t port, X509 *cert, EVP_PKEY *privkey, uint32_t tmout);
void free_ssl_connection(struct ssl_connection *s);
void xor(uint8_t *s1, const uint8_t *s2, int len);
void rand_bytes(uint8_t *buf, int len);
int ssl_read(SSL *ssl, uint8_t *buf, uint32_t len);
int ssl_write(SSL *ssl, const uint8_t *buf, uint32_t len);
uint32_t rand_range(uint32_t min, uint32_t supremum);
char *parse_ip4_to_char(const struct in_addr *in);
char *bin_to_hex(const uint8_t *bin, int len);
char *strdup(const char *s);
uint8_t *read_package(SSL *ssl, uint32_t *outsize);
int write_package(SSL *ssl, uint8_t *data, uint32_t len);
/*int get_phantom_v6_addr(struct in6_addr *res);*/

#if !defined(SIZE_MAX)
#define SIZE_MAX (~((size_t)0))
#endif

#endif
