#include "tunnel.h"
#include "path.h"

static int
exit_check_function(const uint8_t *ciphered)
{
	const uint32_t *d = (const uint32_t *) ciphered;
	/* initialization packet magic */
	if (d[0] == d[1]) {
		if (((d[0] ^ d[2]) == 0xffffffff) && ((d[1] ^ d[3]) == 0xffffffff)) {
			return 1;
		}
	}
	return 0;
}

static int
entry_check_function(const uint8_t *ciphered)
{
	const uint32_t *d = (const uint32_t *) ciphered;
	return ((d[0] ^ d[1]) == 0xffffffff)? 1: 0;
}

static int
brute_rec(const uint8_t *data, struct xkeys **xkeys, int *keys, int cur, int nkeys, int (*check_func)(const uint8_t *), int enc)
{
	int out, out2, innermost, i;
	uint8_t ciphered[TUNNEL_BLOCK_SIZE];
	EVP_CIPHER_CTX ctx;
	if (cur == nkeys) {
		/* abort recursion */
		return 0;
	}
	innermost = (cur + 1 == nkeys);
	for (i = 0; i < xkeys[cur]->nkeys; i++) {
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CipherInit(&ctx, EVP_aes_256_cbc(), xkeys[cur]->keys + i * SYMMETRIC_CIPHER_KEY_LEN,  xkeys[cur]->ivs + i * SYMMETRIC_CIPHER_IV_LEN, enc);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_CipherUpdate(&ctx, ciphered, &out, data, TUNNEL_BLOCK_SIZE);
		EVP_CipherFinal(&ctx, ciphered + out, &out2);
		assert(out + out2 == TUNNEL_BLOCK_SIZE);
		if (innermost && check_func(ciphered)) {
			keys[cur] = i;
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 1;
		}
		if (brute_rec(ciphered, xkeys, keys, cur + 1, nkeys, check_func, enc)) {
			keys[cur] = i;
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 1;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
	}
	return 0;
}

static uint8_t *
brute_force(const uint8_t *data, struct xkeys **xkeys, int nkeys, int (*check_func)(const uint8_t *), int enc)
{
	int *chosen_idxs, i;
	uint8_t *chosen_keys;
	chosen_idxs = alloca(nkeys * sizeof (int));
	chosen_keys = malloc(nkeys * (SYMMETRIC_CIPHER_KEY_LEN + SYMMETRIC_CIPHER_IV_LEN));
	if (chosen_keys == NULL) {
		return NULL;
	}
	if (! brute_rec(data, xkeys, chosen_idxs, 0, nkeys, check_func, enc)) {
		free(chosen_keys);
		return NULL;
	}
	for (i = 0; i < nkeys; i++) {
		memcpy(chosen_keys + i * SYMMETRIC_CIPHER_KEY_LEN, xkeys[i]->keys + chosen_idxs[i] * SYMMETRIC_CIPHER_KEY_LEN, SYMMETRIC_CIPHER_KEY_LEN);
	}
	for (i = 0; i < nkeys; i++) {
		memcpy(chosen_keys + nkeys * SYMMETRIC_CIPHER_KEY_LEN + i * SYMMETRIC_CIPHER_IV_LEN, xkeys[i]->ivs + chosen_idxs[i] * SYMMETRIC_CIPHER_IV_LEN, SYMMETRIC_CIPHER_IV_LEN);
	}
	reverse_array(chosen_keys, nkeys, SYMMETRIC_CIPHER_KEY_LEN);
	reverse_array(chosen_keys + nkeys * SYMMETRIC_CIPHER_KEY_LEN, nkeys, SYMMETRIC_CIPHER_IV_LEN);
	return chosen_keys;
}

static void
create_tunnel_init_reply_package(const uint8_t *keys, const uint8_t *ivs, int nkeys, uint8_t *buf, const uint8_t *contents, int len)
{
	int i, written, written2;
	EVP_CIPHER_CTX ctx;
	uint8_t outbuf[TUNNEL_BLOCK_SIZE];
	uint8_t *out, *in, *tmp;
	assert(len <= TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH);
	memcpy(buf, contents, len);
	SHA1(buf, TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH, buf + (TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH));
	in = buf;
	out = outbuf;
	for (i = 0; i < nkeys; i++) {
		EVP_CIPHER_CTX_init(&ctx);
		EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), keys + i * SYMMETRIC_CIPHER_KEY_LEN, ivs + i * SYMMETRIC_CIPHER_IV_LEN);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_EncryptUpdate(&ctx, out, &written, in, TUNNEL_BLOCK_SIZE);
		EVP_EncryptFinal(&ctx, out + written, &written2);
		EVP_CIPHER_CTX_cleanup(&ctx);
		assert(written + written2 == TUNNEL_BLOCK_SIZE);
		tmp = in;
		in = out;
		out = tmp;
	}
	if (in != buf) {
		memcpy(buf, in, TUNNEL_BLOCK_SIZE);
	}
}

static void
create_exit_tunnel_init_reply_package(const uint8_t *keys, const uint8_t *ivs, int nkeys, uint8_t *buf, struct in6_addr *ap)
{
	bzero(buf, TUNNEL_BLOCK_SIZE);
	if (ap != NULL) {
		create_tunnel_init_reply_package(keys, ivs, nkeys, buf, ap->s6_addr, 16);
	} else {
		create_tunnel_init_reply_package(keys, ivs, nkeys, buf, NULL, 0);
	}
}

static void
create_entry_tunnel_init_reply_package(const uint8_t *keys, const uint8_t *ivs, int nkeys, uint8_t *buf, uint32_t flags)
{
	uint8_t contents[4];
	serialize_32_t(flags, contents);
	bzero(buf, TUNNEL_BLOCK_SIZE);
	create_tunnel_init_reply_package(keys, ivs, nkeys, buf, contents, 4);
}

int
extract_entry_init_reply_package(const uint8_t *received, uint32_t *flags)
{
	uint8_t hash[SHA_DIGEST_LENGTH];
	SHA1(received, TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH, hash);
	if (memcmp(received + (TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH), hash, SHA_DIGEST_LENGTH)) {
		return -1;
	}
	*flags = deserialize_32_t(received);
	return 0;
}

int
extract_exit_init_reply_package(const uint8_t *received, struct in6_addr *ap)
{
	uint8_t hash[SHA_DIGEST_LENGTH];
	assert(sizeof (ap->s6_addr) == 16);
	SHA1(received, TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH, hash);
	if (memcmp(received + (TUNNEL_BLOCK_SIZE - SHA_DIGEST_LENGTH), hash, SHA_DIGEST_LENGTH)) {
		return -1;
	}
	memcpy(ap->s6_addr, received, 16);
	return 0;
}

static struct tunnel *
new_struct_tunnel(const uint8_t *keys, int nkeys, int is_entry, struct ssl_connection *ssl)
{
	int i;
	struct tunnel *t;
	const uint8_t *ivs;
	t = malloc(sizeof (struct tunnel));
	if (t == NULL) {
		return NULL;
	}
	t->ectxs = malloc(nkeys * sizeof (EVP_CIPHER_CTX));
	if (t->ectxs == NULL) {
		free(t);
		return NULL;
	}
	t->dctxs = malloc(nkeys * sizeof (EVP_CIPHER_CTX));
	if (t->dctxs == NULL) {
		free(t->ectxs);
		free(t);
		return NULL;
	}
	ivs = keys + nkeys * SYMMETRIC_CIPHER_KEY_LEN;
	for (i = 0; i < nkeys; i++) {
		EVP_CIPHER_CTX_init(&t->ectxs[i]);
		EVP_CipherInit(&t->ectxs[i], EVP_aes_256_ofb(), keys + i * SYMMETRIC_CIPHER_KEY_LEN, ivs + i * SYMMETRIC_CIPHER_IV_LEN, (is_entry)? 0 : 1);
		EVP_CIPHER_CTX_init(&t->dctxs[i]);
		EVP_CipherInit(&t->dctxs[i], EVP_aes_256_ofb(), keys + i * SYMMETRIC_CIPHER_KEY_LEN, ivs + i * SYMMETRIC_CIPHER_IV_LEN, (is_entry)? 0 : 1);
	}
	reverse_array(t->ectxs, nkeys, sizeof (EVP_CIPHER_CTX));
	reverse_array(t->dctxs, nkeys, sizeof (EVP_CIPHER_CTX));
	t->conn = ssl;
	t->is_entry_tunnel = is_entry;
	t->nkeys = nkeys;
	t->quit = 0;
	return t;
}

void
free_tunnel(struct tunnel *t)
{
	int i;
	assert(t);
	free_ssl_connection(t->conn);
	for (i = 0; i < t->nkeys; i++) {
		EVP_CIPHER_CTX_cleanup(&t->ectxs[i]);
		EVP_CIPHER_CTX_cleanup(&t->dctxs[i]);
	}
	free(t->ectxs);
	free(t->dctxs);
	free(t);
}

struct tunnel *
await_entry_tunnel(const struct in6_addr *own_ap, struct in6_addr *remote_ip, const struct path *path, const struct config *config)
{
	uint8_t buf[TUNNEL_BLOCK_SIZE];
	uint8_t dummy[TUNNEL_BLOCK_SIZE];
	uint8_t original_package[TUNNEL_BLOCK_SIZE];
	uint8_t tip[TUNNEL_BLOCK_SIZE];
	uint8_t outbuf[TUNNEL_BLOCK_SIZE];
	uint8_t ipbuf[4];
	uint8_t *out, *in, *tmp, *keys, *ivs;
	struct ssl_connection *tunnel_conn;
	struct tunnel *t;
	int ret, i, written, written2;
	EVP_CIPHER_CTX ctx;
	assert(path->is_entrypath);
	(void) own_ap;
	ret = ssl_read(path->conn->ssl, original_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		return NULL;
	}
	keys = brute_force(original_package, path->xkeys, path->nkeys, entry_check_function, 0);
	if (keys == NULL) {
		return NULL;
	}
	ivs = keys + path->nkeys * SYMMETRIC_CIPHER_KEY_LEN;
	memcpy(buf, original_package, TUNNEL_BLOCK_SIZE);
	in = buf;
	out = outbuf;
	for (i = path->nkeys - 1; i >= 0; i--) {
		EVP_CIPHER_CTX_init(&ctx);
		EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), keys + i * SYMMETRIC_CIPHER_KEY_LEN, ivs + i * SYMMETRIC_CIPHER_IV_LEN);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_DecryptUpdate(&ctx, out, &written, in, TUNNEL_BLOCK_SIZE);
		EVP_DecryptFinal(&ctx, out + written, &written2);
		assert(written + written2 == TUNNEL_BLOCK_SIZE);
		EVP_CIPHER_CTX_cleanup(&ctx);
		tmp = in;
		in = out;
		out = tmp;
	}
	if (in != buf) {
		memcpy(buf, in, TUNNEL_BLOCK_SIZE);
	}
	if (memcmp(own_ap->s6_addr, buf + 8, 16)) {
		free(keys);
		return NULL;
	}
	memcpy(remote_ip->s6_addr, buf + 8 + 16, 16);
	create_entry_tunnel_init_reply_package(keys, ivs, path->nkeys, tip, 0x0 /*flags whatever*/);
	tunnel_conn = create_ssl_connection(path->peer_ip, path->peer_port, config->communication_certificate, config->private_communication_key);
	if (tunnel_conn == NULL) {
		free(keys);
		return NULL;
	}
	serialize_32_t(2 * TUNNEL_BLOCK_SIZE + SHA_DIGEST_LENGTH, ipbuf);
	ret = ssl_write(tunnel_conn->ssl, ipbuf, 4);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(keys);
		return NULL;
	}
	ret = ssl_write(tunnel_conn->ssl, path->peer_id, SHA_DIGEST_LENGTH);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(keys);
		return NULL;
	}
	ret = ssl_write(tunnel_conn->ssl, original_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(keys);
		return NULL;
	}
	ret = ssl_write(tunnel_conn->ssl, tip, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(keys);
		return NULL;
	}
	/* dummy stuff to make entry tunnel creation symmetric to exit tunnels */
	ret = ssl_read(tunnel_conn->ssl, dummy, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(keys);
		return NULL;
	}
	rand_bytes(dummy, TUNNEL_BLOCK_SIZE);
	ret = ssl_write(tunnel_conn->ssl, dummy, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(keys);
		return NULL;
	}
	/* end dummy stuff */
	t = new_struct_tunnel(keys, path->nkeys, 1, tunnel_conn);
	free(keys);
	if (t == NULL) {
		free_ssl_connection(tunnel_conn);
		return NULL;
	}
	return t;
}

struct tunnel *
create_tunnel(struct in6_addr *ap, const struct path *path)
{
	uint8_t init_package[TUNNEL_BLOCK_SIZE];
	uint8_t *keys;
	struct awaited_connection *aw;
	struct tunnel *t;
	int ret;
	assert(!path->is_entrypath);
	rand_bytes(init_package, TUNNEL_BLOCK_SIZE);
	aw = register_wait_connection(path->peer_ip, path->peer_id);
	if (aw == NULL) {
		return NULL;
	}
	ret = ssl_write(path->conn->ssl, init_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_awaited_connection(aw);
		return NULL;
	}
	ret = wait_for_connection(aw, TMOUT);
	if (ret != 0) {
		free_awaited_connection(aw);
		return NULL;
	}
	if (memcmp(aw->incoming_package + SHA_DIGEST_LENGTH, init_package, TUNNEL_BLOCK_SIZE)) {
		free_awaited_connection(aw);
		return NULL;
	}
	keys = brute_force(aw->incoming_package + SHA_DIGEST_LENGTH + TUNNEL_BLOCK_SIZE, path->xkeys, path->nkeys, exit_check_function, 1);
	if (keys == NULL) {
		free_awaited_connection(aw);
		return NULL;
	}
	create_exit_tunnel_init_reply_package(keys, keys + path->nkeys * SYMMETRIC_CIPHER_KEY_LEN, path->nkeys, init_package, ap);
	ret = ssl_write(aw->incoming_conn->ssl, init_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_awaited_connection(aw);
		free(keys);
		return NULL;
	}
	ret = ssl_read(aw->incoming_conn->ssl, init_package, TUNNEL_BLOCK_SIZE);
	/* receive the success package and throw it away */
	if (ret != 0) {
		free_awaited_connection(aw);
		free(keys);
		return NULL;
	}
	t = new_struct_tunnel(keys, path->nkeys, 0, aw->incoming_conn);
	free(keys);
	if (t == NULL) {
		free_awaited_connection(aw);
		return NULL;
	}
	aw->incoming_conn = NULL;
	free_awaited_connection(aw);
	return t;
}

struct tunnel *
create_ap_reservation_tunnel(const struct path *path)
{
	return create_tunnel(NULL, path);
}

struct tunnel_dummy_package *
create_tunnel_dummy_package(const uint8_t *contents, const struct conn_ctx *conn)
{
	EVP_CIPHER_CTX ctx;
	int written, written2, idx;
	struct tunnel_dummy_package *dp = malloc(sizeof (struct tunnel_dummy_package));
	if (dp == NULL) {
		return NULL;
	}
	idx = rand_range(0, conn->keys->nkeys);
	memcpy(dp->key, conn->keys->keys + idx * SYMMETRIC_CIPHER_KEY_LEN, SYMMETRIC_CIPHER_KEY_LEN);
	memcpy(dp->iv, conn->keys->ivs + idx * SYMMETRIC_CIPHER_IV_LEN, SYMMETRIC_CIPHER_IV_LEN);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), dp->key, dp->iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_EncryptUpdate(&ctx, dp->package, &written, contents, TUNNEL_BLOCK_SIZE);
	EVP_EncryptFinal(&ctx, dp->package + written, &written2);
	EVP_CIPHER_CTX_cleanup(&ctx);
	assert(written + written2 == TUNNEL_BLOCK_SIZE);
	memcpy(dp->original_dummy, contents, TUNNEL_BLOCK_SIZE);
	return dp;
}

uint8_t *
decrypt_tunnel_block(const struct tunnel_dummy_package *dp, const uint8_t *data)
{
	EVP_CIPHER_CTX ctx;
	int written, written2;
	uint8_t *out = malloc(TUNNEL_BLOCK_SIZE);
	if (out == NULL) {
		return NULL;
	}
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), dp->key, dp->iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_DecryptUpdate(&ctx, out, &written, data, TUNNEL_BLOCK_SIZE);
	EVP_DecryptFinal(&ctx, out + written, &written2);
	EVP_CIPHER_CTX_cleanup(&ctx);
	assert(written + written2 == TUNNEL_BLOCK_SIZE);
	return out;
}

int
tunnel_read(struct tunnel *t, uint8_t *buf, int num)
{
	int ret, have, written, err, i;
	uint8_t ibuf[BUFSIZ], *in, *out, *tmp;
	assert(t);
	assert(buf);
	assert(num > 0);
retry:
	ret = SSL_read(t->conn->ssl, ibuf, (num < BUFSIZ)? num : BUFSIZ);
	if (ret <= 0) {
		err = SSL_get_error(t->conn->ssl, ret);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			goto retry;
		} else if (err == SSL_ERROR_ZERO_RETURN || ret == -1) { /* underlying connection is being closed */
			return -1;
		} else {
			/*real error*/
			return -1;
		}
	}
	have = ret;
	assert(have > 0 && have <= BUFSIZ);
	in = ibuf;
	out = buf;
	for (i = 0; i < t->nkeys; i++) {
		assert(EVP_CipherUpdate(&t->ectxs[i], out, &written, in, have));
		assert(written == have);
		tmp = in;
		in = out;
		out = tmp;
	}
	if (in != buf) {
		memcpy(buf, in, have);
	}
	return have;
}

int
tunnel_write(struct tunnel *t, const uint8_t *buf, int num)
{
	int written, i, to_write;
	uint8_t buf1[BUFSIZ], buf2[BUFSIZ], *in, *out, *tmp;
	assert(t);
	assert(buf);
	assert(num > 0);
	to_write = (num < BUFSIZ)? num : BUFSIZ;
	out = buf1;
	assert(EVP_CipherUpdate(&t->dctxs[0], out, &written, buf, to_write));
	assert(written == to_write);
	in = out;
	out = buf2;
	for (i = 1; i < t->nkeys; i++) {
		assert(EVP_CipherUpdate(&t->dctxs[i], out, &written, in, to_write));
		assert(written == to_write);
		tmp = in;
		in = out;
		out = tmp;
	}
	return (ssl_write(t->conn->ssl, in, to_write) == 0)? to_write : -1;
}
