#include "rc4rand.h"

static const uint8_t zero[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct rc4_rand *
rc4_rand_init(const uint8_t *seed, int len)
{
	struct rc4_rand *r = malloc(sizeof (struct rc4_rand));
	if (r == NULL) {
		return NULL;
	}
	RC4_set_key(&r->key, len, seed);
	return r;
}

void
rc4_rand_bytes(struct rc4_rand *r, uint8_t *buf, int len)
{
		int i;
		for (i = 0; len >= 16; i++) {
			RC4(&r->key, 16, zero, buf + i * 16);
			len -= 16;
		}
		RC4(&r->key, len, zero, buf + i * 16);
}

void
rc4_rand_free(struct rc4_rand *r)
{
	free(r);
}
