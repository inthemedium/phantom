#ifndef __HAVE_X_509_FLAT_H__
#define __HAVE_X_509_FLAT_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include "helper.h"

struct X509_flat {
	uint8_t *data;
	size_t len;
};

struct X509_flat *new_X509_flat(void);
uint8_t *serialize_X509_flat(const struct X509_flat *x);
struct X509_flat *deserialize_X509_flat(const uint8_t *serialized);
void free_X509_flat(struct X509_flat *x);
struct X509_flat *read_x509_from_file_flat(const char *path);
X509 *read_x509_from_x509_flat(const struct X509_flat *fx);
size_t X509_serialized_size(const struct X509_flat *x);
struct X509_flat *flatten_X509(X509 *x);
int X509_compare(X509 *a, X509 *b);
int X509_compare_mixed(struct X509_flat *a, X509 *b);
int X509_compare_flat(struct X509_flat *a,  struct X509_flat *b);
int X509_hash(X509 *c, uint8_t *buf);
X509 *clone_cert(X509 *x);

#endif
