#include "helper.h"

void
randomize_array(void *base, const size_t nmemb, size_t size)
{
	uint32_t i, pos;
	uint8_t *buf;
	uint8_t *array = (uint8_t *) base;
	buf = alloca(size);
	for (i = 0; i < nmemb; i++) {
		pos = rand_range(0, nmemb);
		if (pos == i) {
			continue;
		}
		memcpy(buf, array + i * size, size);
		memcpy(array + i * size, array + pos * size, size);
		memcpy(array + pos * size, buf, size);
	}
}

void
reverse_array(void *base, size_t nmemb, size_t size)
{
	uint32_t i;
	uint8_t *buf;
	uint8_t *array = (uint8_t *) base;
	buf = alloca(size);
	for (i = 0; i < nmemb / 2; i++) {
		memcpy(buf, array + i * size, size);
		memcpy(array + i * size, array + (nmemb - i - 1) * size, size);
		memcpy(array + (nmemb - i - 1) * size, buf, size);
	}
}

void
hexdump(const void *buf, int size)
{
	int i = 1;
	const char *cbuf = (const char *)buf;
	printf("%d:  ", i - 1);
	for (; i <= size; i++) {
		printf("%02X ", cbuf[i - 1] & 0xff);
		if (i % 8 == 0) {
			putchar('\n');
			printf("%d:  ", i - 1);
		}
	}
	putchar('\n');
}

X509 *
read_x509_from_file(const char *path)
{
	BIO *in = NULL;
	X509 *x = NULL;

	if (path == NULL) {
		return NULL;
	}

	in = BIO_new_file(path, "r");
	if (in == NULL) {
		return NULL;
	}
	x = PEM_read_bio_X509(in, NULL, 0, NULL);
	BIO_free(in);

	return x;
}

void
serialize_32_t(uint32_t t, uint8_t *buf)
{
	assert(buf != NULL);
	buf[0] = (t >> 24) & 0xff;
	buf[1] = (t >> 16) & 0xff;
	buf[2] = (t >> 8) & 0xff;
	buf[3] = (t) & 0xff;
}

uint32_t
deserialize_32_t(const uint8_t *buf)
{
	assert(buf != NULL);
	return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
}

void
serialize_16_t(uint16_t t, uint8_t *buf)
{
	assert(buf != NULL);
	buf[0] = (uint8_t) (t >> 8);
	buf[1] = (uint8_t) (t);
}

uint16_t
deserialize_16_t(const uint8_t *buf)
{
	assert(buf != NULL);
	return ((((uint16_t) (buf[0])) << 8) + buf[1]);
}

EVP_PKEY *
rsa_to_pkey(RSA *rsa)
{
	EVP_PKEY *key;
	int ret;
	key = EVP_PKEY_new();
	if (key == NULL) {
		return NULL;
	}
	ret = EVP_PKEY_set1_RSA(key, rsa);
	if (ret != 1) {
		EVP_PKEY_free(key);
		return NULL;
	}
	return key;
}

struct ssl_connection *
create_ssl_connection(const char *ip, uint16_t port, X509 *cert, EVP_PKEY *privkey)
{
	return create_ssl_connection_tmout(ip, port, cert, privkey, 0);
}

struct ssl_connection *
create_ssl_connection_tmout(const char *ip, uint16_t port, X509 *cert, EVP_PKEY *privkey, uint32_t tmout)
{
	SSL_CTX *ctx;
	int sd;
	int ret;
	struct sockaddr_in sa;
	SSL *ssl;
	struct ssl_connection *sc;

	ctx = SSL_CTX_new (SSLv23_client_method());
	if (ctx == NULL) {
		return NULL;
	}
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */

	sd = socket (AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	bzero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr (ip);
	sa.sin_port = htons(port);
	if (tmout) {
		uint32_t flags;
		struct pollfd fds[1];
		bzero(&fds[0], sizeof (struct pollfd));
		fds[0].fd = sd;
		fds[0].events = POLLIN | POLLOUT;
		flags = fcntl(sd, F_GETFL);
		ret = fcntl(sd, F_SETFL, flags | O_NONBLOCK);
		if (ret == -1) {
			SSL_CTX_free(ctx);
			close(sd);
			return NULL;
		}
		errno = 0;
		ret = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
		if (ret == -1) {
			if (errno != EINPROGRESS) {
				SSL_CTX_free(ctx);
				close(sd);
				return NULL;
			}
		}
		ret = poll(fds, 1, 1000 * tmout);
		if (ret <= 0) {
			SSL_CTX_free(ctx);
			close(sd);
			return NULL;
		}
		ret = fcntl(sd, F_SETFL, flags);
		if (ret == -1) {
			SSL_CTX_free(ctx);
			close(sd);
			return NULL;
		}
	} else {
		ret = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
		if (ret == -1) {
			SSL_CTX_free(ctx);
			close(sd);
			return NULL;
		}
	}

	/* ----------------------------------------------- */
	/* Now we have TCP conncetion. Start SSL negotiation. */

	ssl = SSL_new(ctx);
	SSL_CTX_free(ctx);
	if (ssl == NULL) {
		SSL_free(ssl);
		close(sd);
		return NULL;
	}
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	if (cert != NULL) {
		if (SSL_use_certificate(ssl, cert) <= 0) {
			close(sd);
			SSL_free(ssl);
			return NULL;
		}
	}
	if (privkey != NULL) {
		if (SSL_use_PrivateKey(ssl, privkey) <= 0) {
			close(sd);
			SSL_free(ssl);
			return NULL;
		}
	}
	if (privkey != NULL && cert != NULL) {
		if (! SSL_check_private_key(ssl)) {
			close(sd);
			SSL_free(ssl);
			return NULL;
		}
	}
	ret = SSL_set_fd(ssl, sd);
	if (ret != 1) {
		SSL_free(ssl);
		close(sd);
		return NULL;
	}
	errno = 0;
	ret = SSL_connect(ssl);
	if (ret < 0) {
#if 0
		printf("problem talking to %s ", ip);
		switch (SSL_get_error(ssl, ret)) {
			case SSL_ERROR_NONE:
				printf("no error\n");
				break;
			case SSL_ERROR_ZERO_RETURN:
				printf("SSL_ERROR_ZERO_RETURN\n");
				break;
			case SSL_ERROR_WANT_READ:
				printf("SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				printf("SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				printf("SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				printf("SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				printf("SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_SYSCALL:
				printf("SSL_ERROR_SYSCALL\n");
				perror(NULL);
				break;
			case SSL_ERROR_SSL:
				printf("SSL_ERROR_SSL\n");
				break;
		}
#endif
		SSL_free(ssl);
		close(sd);
		return NULL;
	}
	sc = calloc(sizeof (struct ssl_connection), 1);
	if (sc == NULL) {
		SSL_free(ssl);
		close(sd);
		return NULL;
	}
	sc->peer_cert = SSL_get_peer_certificate(ssl);
	/* FIXME SSL_get_verify_result */
	if (sc->peer_cert == NULL) {
		SSL_free(ssl);
		close(sd);
		free(sc);
		return NULL;
	}
	sc->ssl = ssl;
	sc->socket = sd;
	return sc;
}

void
free_ssl_connection(struct ssl_connection *s)
{
	int iRet;
	if (s->ssl != NULL) {
		iRet = SSL_get_shutdown(s->ssl);
		if (iRet >= 0) SSL_shutdown(s->ssl);
		SSL_free(s->ssl);
	}
	if (s->socket != 0) {
		close(s->socket);
	}
	if (s->peer_cert != NULL) {
		X509_free(s->peer_cert);
	}
	free(s);
}

uint32_t
rand_range(uint32_t min, uint32_t supremum)
{
	uint32_t irand, range;
	int retries;
	assert(min < supremum);
	range = supremum - min;
	retries = 5;
	do {
		rand_bytes((uint8_t *) &irand, 4);
	} while ((irand > UINT_MAX - (UINT_MAX % range)) && retries--);
	return min + (irand % range);
}

char *
parse_ip4_to_char(const struct in_addr *in)
{
	char *ret, *out;
	static pthread_mutex_t ntoa_protect_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&ntoa_protect_mutex);
	ret = inet_ntoa(*in);
	out = strdup(ret);
	pthread_mutex_unlock(&ntoa_protect_mutex);
	return out;
}

char *
ip4_to_char(uint32_t in)
{
	struct in_addr ina;
	ina.s_addr = in;
	return parse_ip4_to_char(&ina);
}

/* s1 = s1 xor s2 */
void
xor(uint8_t *s1, const uint8_t *s2, int len)
{
	int i;
	uint32_t *i1;
	const uint32_t *i2;
	assert(len % 4 == 0);
	i1 = (uint32_t *) s1;
	i2 = (const uint32_t *) s2;
	for (i = 0; i < len / 4; i++) {
		i1[i] ^= i2[i];
	}
}

void rand_bytes(uint8_t *buf, int len)
{
	int retries = 5;
	while (retries--) {
		if (RAND_bytes(buf, len)) {
			return;
		}
	}
	printf("RNG ran out of entropy - continuing with %d pseudorandom bytes\n", len);
}

int
ssl_read(SSL *ssl, uint8_t *buf, uint32_t len)
{
	int ret, err;
	uint32_t have;
	have = 0;
	while (have < len) {
retry:
		ret = SSL_read(ssl, buf + have, len - have);
		if (ret <= 0) {
			err = SSL_get_error(ssl, ret);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				goto retry;
			} else if (err == SSL_ERROR_ZERO_RETURN || ret == -1) { /* underlying connection is being closed */
				return -1;
			} else {
				/*real error*/
				return -1;
			}
		} else {
			have += ret;
		}
	}
	assert(have == len);
	return 0;
}

int
ssl_write(SSL *ssl, const uint8_t *buf, uint32_t len)
{
	int ret, err;
	uint32_t have;
	have = 0;
	while (have < len) {
retry:
		ret = SSL_write(ssl, buf + have, len - have);
		err = SSL_get_error(ssl, ret);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			goto retry;
		}
		if (err == SSL_ERROR_ZERO_RETURN || ret == -1) { /* underlying connection is being closed */
			return -1;
		}
		have += ret;
	}
	assert(have == len);
	return 0;
}

char *
bin_to_hex(const uint8_t *bin, int len)
{
	int i, pos;
	char *out;
	static const char *hex = "0123456789ABCDEF";
	out = malloc(len * 2 + 1);
	if (out == NULL) {
		return NULL;
	}
	pos = 0;
	for (i = 0; i < len; i++) {
		out[pos++] = hex[bin[i] >> 4 & 0x0f];
		out[pos++] = hex[bin[i] & 0x0f];
	}
	assert(pos == len * 2);
	out[pos] = '\0';
	return out;
}

char *
strdup(const char *s)
{
	char *out;
	int len;
	len = strlen(s) + 1;
	out = malloc(len);
	if (out == NULL) {
		return NULL;
	}
	memcpy(out, s, len);
	return out;
}

uint8_t *
read_package(SSL *ssl, uint32_t *outsize)
{
	int ret;
	uint8_t buf[4];
	uint32_t size;
	uint8_t *package;
	ret = ssl_read(ssl, buf, 4);
	if (ret != 0) {
		return NULL;
	}
	size = deserialize_32_t(buf);
	package = malloc(size);
	if (package == NULL) {
		return NULL;
	}
	ret = ssl_read(ssl, package, size);
	if (ret != 0) {
		free(package);
		return NULL;
	}
	*outsize = size;
	return package;

}

int
write_package(SSL *ssl, uint8_t *data, uint32_t len)
{
	int ret;
	uint8_t buf[4];
	serialize_32_t(len, buf);
	ret = ssl_write(ssl, buf, 4);
	if (ret != 0) {
		return -1;
	}
	return ssl_write(ssl, data, len);
}

#if 0
int
get_phantom_v6_addr(struct in6_addr *res)
{
	/* FIXME this is not a nice way to get the adress, however rtnetlink is
	 * complex and oi have not gotten it working in hours, it is the default
	 * way however for v6 it would seem*/
	FILE *f;
	char buf[32 + 7 + 1];
	char ifname[IFNAMSIZ + 1];
	int d1, d2, d3, d4, ret;
	f = fopen("/proc/net/if_inet6", "r");
	if (f == NULL) {
		return -1;
	}
	/*fd0025223493ffffffff00e0815867ab 07 50 00 80  phantom */
	memset(buf, 0x3a, sizeof (buf));
	while (1) {
		ret = fscanf(f, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c %d %d %d %d %s\n", &buf[0], &buf[1], &buf[2], &buf[3], &buf[5], &buf[6], &buf[7], &buf[8], &buf[10], &buf[11], &buf[12], &buf[13], &buf[15], &buf[16], &buf[17], &buf[18], &buf[20], &buf[21], &buf[22], &buf[23], &buf[25], &buf[26], &buf[27], &buf[28], &buf[30], &buf[31], &buf[32], &buf[33], &buf[35], &buf[36], &buf[37], &buf[38], &d1, &d2, &d3, &d4, ifname);
		if (ret == EOF) {
			fclose(f);
			return -1;
		}
		if (ret != 37) {
			continue;
		}
		buf[39] = 0;
		ifname[IFNAMSIZ] = 0;
		if (! strcmp(ifname, "phantom")) {
			ret = inet_pton(AF_INET6, buf, res);
			if (ret != 1) {
				continue;
			}
			fclose(f);
			return 0;
		}
	}
}
#endif
