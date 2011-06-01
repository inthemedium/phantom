#ifndef __HAVE_RC_4_RAND_H__
#define __HAVE_RC_4_RAND_H__

#include <openssl/rc4.h>
#include <inttypes.h>
#include <stdlib.h>

struct rc4_rand {
	RC4_KEY key;
};

struct rc4_rand *rc4_rand_init(const uint8_t *seed, int len);
void rc4_rand_bytes(struct rc4_rand *r, uint8_t *buf, int len);
void rc4_rand_free(struct rc4_rand *r);
#endif
