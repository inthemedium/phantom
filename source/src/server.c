#include "server.h"
#include "helper.h"
#include "tunnel.h"
#include <sys/select.h>

static struct server server;
static pthread_mutex_t create_tunnel_lock = PTHREAD_MUTEX_INITIALIZER;

static struct awaited_connection *
register_wait_connection_inner(const char *ip, const uint8_t *id, int permanent)
{
	int ret;
	struct awaited_connection *c = calloc(1, sizeof (struct awaited_connection));
	if (c == NULL) {
		return NULL;
	}
	c->permanent = permanent;
	c->incoming_conn = calloc(1, sizeof (struct ssl_connection));
	if (c->incoming_conn == NULL) {
		free(c);
		return NULL;
	}
	if (ip != NULL) {
		c->ip = strdup(ip);
		if (c->ip == NULL) {
			free(c->incoming_conn);
			free(c);
			return NULL;
		}
	}
	memcpy(c->id, id, SHA_DIGEST_LENGTH);
	ret = sem_init(&c->sem, 0, 0);
	if (ret != 0) {
		free(c->ip);
		free(c->incoming_conn);
		free(c);
		return NULL;
	}
	if (permanent) {
		ret = sem_init(&c->entry_ok, 0, 0);
		if (ret != 0) {
			sem_destroy(&c->sem);
			free(c->ip);
			free(c->incoming_conn);
			free(c);
			return NULL;
		}
	}
	pthread_mutex_lock(&server.awaited_mutex);
	LIST_insert(&server.awaited_list, c);
	pthread_mutex_unlock(&server.awaited_mutex);
	return c;
}

struct awaited_connection *
register_wait_connection(const char *ip, const uint8_t *id)
{
	return register_wait_connection_inner(ip, id, 0);
}

static struct awaited_connection *
register_wait_connection_permanent(const char *ip, const uint8_t *id)
{
	return register_wait_connection_inner(ip, id, 1);
}

int
wait_for_connection(struct awaited_connection *w, int timeout)
{
	int ret;
	ret = clock_gettime(CLOCK_REALTIME, &w->timeout);
	if (ret != 0) {
		return -1;
	}
	w->timeout.tv_sec += timeout;
	do {
		errno = 0;
		ret = sem_timedwait(&w->sem, &w->timeout);
	} while (errno == EINTR);
	return ret;
}

void
free_awaited_connection(struct awaited_connection *c)
{
	struct awaited_connection *help1, *help2;
	pthread_mutex_lock(&server.awaited_mutex);
	LIST_for_all(&server.awaited_list, help1, help2) {
		if (help1 == c) {
			LIST_remove(help1);
		}
	}
	pthread_mutex_unlock(&server.awaited_mutex);
	if (c->incoming_conn != NULL) {
		free_ssl_connection(c->incoming_conn);
	}
	if (c->ip != NULL) {
		free(c->ip);
	}
	if (c->incoming_package != NULL) {
		free(c->incoming_package);
	}
	if (c->permanent) {
		sem_destroy(&c->entry_ok);
	}
	free(c);
}

static struct ssl_connection *
send_ap_connection_request(const struct in6_addr *ap)
{
	int ret, i, num;
	struct ssl_connection *out;
	char **ip_adresses;
	uint16_t *ports;
	uint8_t hash[SHA_DIGEST_LENGTH];
	ret = get_entry_nodes_for_ap_adress(&ip_adresses, &ports, &num, ap);
	if (ret != 0) {
		return NULL;
	}
	assert(num > 0); /* make code analyzer shut up */
	for (i = 0; i < num; i++) {
		out = create_ssl_connection_tmout(ip_adresses[i], ports[i], server.certificate, server.privkey, TMOUT);
		if (out != NULL) {
			break;
		}
	}
	free(ip_adresses);
	free(ports);
	if (out == NULL) {
		return NULL;
	}
	SHA1(ap->s6_addr, sizeof (ap->s6_addr), hash);
	ret = write_package(out->ssl, hash, SHA_DIGEST_LENGTH);
	if (ret != 0) {
		free_ssl_connection(out);
		return NULL;
	}
	return out;
}

static void
free_worker_data(struct worker_data *wd)
{
	if (wd->client_cert != NULL) {
		X509_free(wd->client_cert);
	}
	if (wd->socket != -1) {
		close(wd->socket);
	}
	free(wd);
}

struct forward_data {
	const uint8_t *key;
	const uint8_t *iv;
	SSL *in;
	SSL *out;
};

static void
forwarder(struct forward_data *f)
{
	uint8_t in[BUFSIZ], out[BUFSIZ];
	int written, ret, inlen, err;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, EVP_aes_256_ofb(), f->key, f->iv);
	while (1) {
		ret = SSL_read(f->in, in, BUFSIZ);
		err = SSL_get_error(f->in, ret);
		inlen = ret;
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			assert(ret < 0);
			continue;
		}
		if (err == SSL_ERROR_ZERO_RETURN || ret == -1) { /* underlying connection is being closed */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return;
		}
		assert(EVP_DecryptUpdate(&ctx, out, &written, in, inlen));
		ret = ssl_write(f->out, out, written);
		if (ret != 0) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			return;
		}
	}
}

static void
forward_traffic(const uint8_t *key, const uint8_t *iv, SSL *encrypt_to, SSL *decrypt_to)
{
	int ret;
	pthread_t tid1, tid2;
	struct forward_data f1, f2;
	f1.key = key;
	f1.iv = iv;
	f1.in = encrypt_to;
	f1.out = decrypt_to;
	f2.key = key;
	f2.iv = iv;
	f2.out = encrypt_to;
	f2.in = decrypt_to;
	ret = pthread_create(&tid1, NULL, (void *(*)(void *)) forwarder, &f1);
	if (ret != 0) {
		return;
	}
	ret = pthread_create(&tid2, NULL, (void *(*)(void *)) forwarder, &f2);
	if (ret != 0) {
		pthread_join(tid1, NULL);
		return;
	}
	pthread_join(tid1, NULL);
	pthread_join(tid2, NULL);
}

static int
verify_callback(int i, X509_STORE_CTX *x)
{
	(void) i;
	(void) x;
	/* return always true because we accept all certificates - we just need
	 * to make shure there is one */
	return 1;
}

static int
forward_setup_array(SSL *ssl, uint8_t *array, uint32_t len)
{
	int ret;
	uint8_t preface[4];
	serialize_32_t(len, preface);
	ret = ssl_write(ssl, preface, 4);
	if (ret != 0) {
		return -1;
	}
	return ssl_write(ssl, array, len);
}

static struct conn_ctx *
handle_first_package(const struct worker_data *wd, const uint8_t *package, uint32_t len)
{
	char *from_ip;
	uint8_t *next;
	uint32_t outsize;
	struct conn_ctx *conn;
	int ret;
	conn = new_conn_ctx();
	if (conn == NULL) {
		return NULL;
	}
	from_ip = parse_ip4_to_char(&wd->ip.sin_addr);
	if (from_ip == NULL) {
		free_conn_ctx(conn);
		return NULL;
	}
	next = handle_first_round_setup_array(server.config, package + SHA_DIGEST_LENGTH, len - SHA_DIGEST_LENGTH, package, from_ip, conn, &outsize);
	free(from_ip);
	if (next == NULL) {
		free_conn_ctx(conn);
		return NULL;
	}
	conn->to_next = create_ssl_connection(conn->next_ip, conn->next_port, server.config->communication_certificate, server.config->private_communication_key);
	if (conn->to_next == NULL) {
		free(next);
		free_conn_ctx(conn);
		return NULL;
	}
	if (! X509_compare(conn->next_communication_certificate, conn->to_next->peer_cert)) {
		free(next);
		free_conn_ctx(conn);
		return NULL;
	}
	ret = forward_setup_array(conn->to_next->ssl, next, outsize);
	free(next);
	if (ret != 0) {
		free_conn_ctx(conn);
		return NULL;
	}
	return conn;
}

static struct conn_ctx *
handle_snd_package(uint8_t *package, uint32_t len, const struct conn_ctx *old, struct awaited_connection **waitfor)
{
	struct conn_ctx *new;
	uint8_t *next;
	uint32_t outsize;
	int ret;
	new = new_conn_ctx();
	if (new == NULL) {
		return NULL;
	}
	next = handle_second_round_setup_array(server.config, package + SHA_DIGEST_LENGTH, len - SHA_DIGEST_LENGTH, package, old, new, &outsize);
	if (next == NULL) {
		free_conn_ctx(new);
		return NULL;
	}
	if (new->flags & X_NODE) {
		*waitfor = register_wait_connection(new->prev_ip, new->prev_id);
		if (*waitfor == NULL) {
			free(next);
			free_conn_ctx(new);
			return NULL;
		}
	} else {
		*waitfor = NULL;
	}
	ret = forward_setup_array(old->to_next->ssl, next, outsize);
	free(next);
	if (ret != 0) {
		free_conn_ctx(new);
		return NULL;
	}
	return new;
}

static int
pass_x_package_on(struct conn_ctx *conn)
{
	int ret;
	uint8_t buf[4];

	conn->to_next = create_ssl_connection(conn->next_ip, conn->next_port, server.config->communication_certificate, server.config->private_communication_key);
	if (conn->to_next == NULL) {
		printf("next x connect failed\n");
		return -1;
	}
	if (! X509_compare(conn->next_communication_certificate, conn->to_next->peer_cert)) {
		return -1;
	}
	serialize_32_t(SHA_DIGEST_LENGTH, buf);
	ret = ssl_write(conn->to_next->ssl, buf, 4);
	if (ret != 0) {
		return -1;
	}
	ret = ssl_write(conn->to_next->ssl, conn->next_id, SHA_DIGEST_LENGTH);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

static struct entry_worker *
prepare_entry_worker(const struct conn_ctx *conn, const struct ssl_connection *peer, struct ssl_connection *incoming_conn)
{
	int ret;
	struct entry_worker *e = calloc(1, sizeof (struct entry_worker));
	if (e == NULL) {
		return NULL;
	}
	ret = pthread_attr_init(&e->attr);
	if (ret != 0) {
		free(e);
		return NULL;
	}
	e->peer = peer;
	e->incoming_conn = incoming_conn;
	e->conn = conn;
	return e;
}

static void
free_entry_worker(struct entry_worker *ew)
{
	/*free_ssl_connection(ew->incoming_conn);*/
	pthread_attr_destroy(&ew->attr);
	free(ew);
}

static struct exit_worker *
prepare_exit_worker(struct tunnel_dummy_package *dp, const struct conn_ctx *conn, const struct ssl_connection *peer)
{
	int ret;
	struct exit_worker *ew = calloc(1, sizeof (struct exit_worker));
	if (ew == NULL) {
		return NULL;
	}
	ret = pthread_attr_init(&ew->attr);
	if (ret != 0) {
		free(ew);
		return NULL;
	}
	ew->reserve_ap = (conn->flags & RESERVE_AP)? 1 : 0;
	ew->dp = dp;
	ew->conn = conn;
	ew->peer = peer;
	return ew;
}

static void
free_exit_worker(struct exit_worker *ew)
{
	pthread_attr_destroy(&ew->attr);
	free(ew->dp);
	free(ew);
}

static int
exit_worker(struct exit_worker *ew)
{
	int ret, written, written2;
	socklen_t peer_len;
	char *ip;
	uint8_t buf[4];
	struct in6_addr ap;
	uint8_t tip[TUNNEL_BLOCK_SIZE];
	uint8_t tipcrypt[TUNNEL_BLOCK_SIZE];
	uint8_t init_reply_package[TUNNEL_BLOCK_SIZE];
	struct sockaddr_in sa;
	struct ssl_connection *tunnel_conn, *out_tunnel;
	uint8_t *init_reply_package_dec;
	uint32_t *itip = (uint32_t *) tip;
	EVP_CIPHER_CTX ctx;
	peer_len = sizeof (sa);
	rand_bytes(tip, 4);
	itip[1] = itip[0];
	itip[2] = ~itip[0];
	itip[3] = ~itip[1];
	assert(((itip[2] ^ itip[0]) == 0xffffffff) && ((itip[3] ^ itip[1]) == 0xffffffff));
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), ew->dp->key, ew->dp->iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_DecryptUpdate(&ctx, tipcrypt, &written, tip, TUNNEL_BLOCK_SIZE);
	EVP_DecryptFinal(&ctx, tipcrypt + written, &written2);
	assert(written + written2 == TUNNEL_BLOCK_SIZE);
	ret = getpeername(ew->peer->socket, (struct sockaddr *) &sa, &peer_len);
	if (ret != 0) {
		free_exit_worker(ew);
		return -1;
	}
	ip = ip4_to_char(sa.sin_addr.s_addr);
	tunnel_conn = create_ssl_connection(ip, /*htons(sa.sin_port) XXX */8080, server.certificate, server.privkey);
	free(ip);
	if (tunnel_conn == NULL) {
		free_exit_worker(ew);
		return -1;
	}
	if (! X509_compare(tunnel_conn->peer_cert, ew->peer->peer_cert)) {
		free_exit_worker(ew);
		return -1;
	}
	serialize_32_t(2 * TUNNEL_BLOCK_SIZE + SHA_DIGEST_LENGTH, buf);
	ret = ssl_write(tunnel_conn->ssl, buf, 4);
	if (ret != 0) {
		free_exit_worker(ew);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, ew->conn->peer_id, SHA_DIGEST_LENGTH);
	if (ret != 0) {
		free_exit_worker(ew);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, ew->dp->original_dummy, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_exit_worker(ew);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, tipcrypt, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_exit_worker(ew);
		return -1;
	}
	ret = ssl_read(tunnel_conn->ssl, init_reply_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free_exit_worker(ew);
		return -1;
	}
	init_reply_package_dec = decrypt_tunnel_block(ew->dp, init_reply_package);
	if (init_reply_package_dec == NULL) {
		free_ssl_connection(tunnel_conn);
		free_exit_worker(ew);
		return -1;
	}
	ret = extract_exit_init_reply_package(init_reply_package_dec, &ap);
	free(init_reply_package_dec);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free_exit_worker(ew);
		return -1;
	}
	if (ew->reserve_ap) {
		struct in6_addr rap;
		uint8_t obuf[16];
		int writ;
		EVP_CIPHER_CTX dctx;
		assert(sizeof (rap.s6_addr) == 16);
		get_free_ap_adress(&rap);
		rand_bytes(init_reply_package, TUNNEL_BLOCK_SIZE);
		ret = ssl_write(tunnel_conn->ssl, init_reply_package, TUNNEL_BLOCK_SIZE);
		if (ret != 0) {
			free_ssl_connection(tunnel_conn);
			free_exit_worker(ew);
			return -1;
		}
		EVP_CIPHER_CTX_init(&dctx);
		EVP_DecryptInit(&dctx, EVP_aes_256_ofb(), ew->dp->key, ew->dp->iv);
		EVP_DecryptUpdate(&dctx, obuf, &writ, rap.s6_addr, sizeof (rap.s6_addr));
		EVP_DecryptFinal(&dctx, obuf + writ, &writ);
		EVP_CIPHER_CTX_cleanup(&dctx);
		ret = ssl_write(tunnel_conn->ssl, obuf, sizeof (rap.s6_addr));
		if (ret != 0) {
			free_ssl_connection(tunnel_conn);
			free_exit_worker(ew);
			return -1;
		}
		free_ssl_connection(tunnel_conn);
		free_exit_worker(ew);
		return (ret != 0)? -1 : 0;
	}
	/* try to establish an outgoing connection to the stated ap adress */
	out_tunnel = send_ap_connection_request(&ap);
	if (out_tunnel == NULL) {
		goto out;
	} /* external conn succeeded*/
	printf("external conn succeeded\n");
	/* inform anonoymized node about successful creation of connection via random data */
	rand_bytes(init_reply_package, TUNNEL_BLOCK_SIZE);
	ret = ssl_write(tunnel_conn->ssl, init_reply_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		goto out;
	}
	forward_traffic(ew->dp->key, ew->dp->iv, tunnel_conn->ssl, out_tunnel->ssl);
out:
	free_ssl_connection(tunnel_conn);
	free_exit_worker(ew);
	return 0;
}

static int
entry_worker(struct entry_worker *ew)
{
	uint8_t crypto_key_init_block[TUNNEL_BLOCK_SIZE];
	uint8_t dummy[TUNNEL_BLOCK_SIZE];
	uint8_t cki_received[TUNNEL_BLOCK_SIZE];
	uint32_t *p;
	int ret, written, written2;
	uint32_t flags;
	struct tunnel_dummy_package *dp;
	struct awaited_connection *aw;
	EVP_CIPHER_CTX ctx;
	assert(TUNNEL_BLOCK_SIZE >= 16);
	rand_bytes(crypto_key_init_block, 4);
	p = (uint32_t *) crypto_key_init_block;
	p[1] = ~p[0];
	assert((p[0] ^ p[1]) == 0xffffffff);
	/* set ap belonging to this tunnel */
	memcpy(crypto_key_init_block + 8, ew->conn->ap.s6_addr, 16);
	/*FIXME set 16 byte remote ip */
	rand_bytes(crypto_key_init_block + 8 + 16, 16);
	dp = create_tunnel_dummy_package(crypto_key_init_block, ew->conn);
	if (dp == NULL) {
		free_entry_worker(ew);
		return -1;
	}
	pthread_mutex_lock(&create_tunnel_lock);
	aw = register_wait_connection(ew->conn->peer_ip, ew->conn->peer_id);
	if (aw == NULL) {
		pthread_mutex_unlock(&create_tunnel_lock);
		free(dp);
		free_entry_worker(ew);
		return -1;
	}
	ret = ssl_write(ew->peer->ssl, dp->package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		pthread_mutex_unlock(&create_tunnel_lock);
		free_awaited_connection(aw);
		free(dp);
		free_entry_worker(ew);
		return -1;
	}
	ret = wait_for_connection(aw, TMOUT);
	pthread_mutex_unlock(&create_tunnel_lock);
	if (ret != 0) {
		free_awaited_connection(aw);
		free(dp);
		free_entry_worker(ew);
		return -1;
	}
	if (! X509_compare(ew->peer->peer_cert, ew->conn->peer_cert)) {
		printf("cert mismatch2\n");
		free(dp);
		free_entry_worker(ew);
		return -1;
	}
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), dp->key, dp->iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_DecryptUpdate(&ctx, cki_received, &written, aw->incoming_package + SHA_DIGEST_LENGTH, TUNNEL_BLOCK_SIZE);
	EVP_DecryptFinal(&ctx, cki_received + written, &written2);
	assert(written + written2 == TUNNEL_BLOCK_SIZE);
	if (memcmp(crypto_key_init_block, cki_received, TUNNEL_BLOCK_SIZE)) {
		free(dp);
		free_awaited_connection(aw);
		free_entry_worker(ew);
		return -1;
	}
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), dp->key, dp->iv);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_DecryptUpdate(&ctx, cki_received, &written, aw->incoming_package + SHA_DIGEST_LENGTH + TUNNEL_BLOCK_SIZE, TUNNEL_BLOCK_SIZE);
	EVP_DecryptFinal(&ctx, cki_received + written, &written2);
	assert(written + written2 == TUNNEL_BLOCK_SIZE);
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (extract_entry_init_reply_package(cki_received, &flags) != 0) {
		free(dp);
		free_awaited_connection(aw);
		free_entry_worker(ew);
		return -1;
	}
	/* dummy stuff to make entry tunnels symmetric to exit tunnels */
	rand_bytes(dummy, TUNNEL_BLOCK_SIZE);
	ret = ssl_write(aw->incoming_conn->ssl, dummy, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free(dp);
		free_awaited_connection(aw);
		free_entry_worker(ew);
		return -1;
	}
	ret = ssl_read(aw->incoming_conn->ssl, dummy, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free(dp);
		free_awaited_connection(aw);
		free_entry_worker(ew);
		return -1;
	}
	/* end dummy stuff */
	forward_traffic(dp->key, dp->iv, ew->incoming_conn->ssl, aw->incoming_conn->ssl);
	free(dp);
	free_awaited_connection(aw);
	free_entry_worker(ew);
	return 0;
}

static int
become_tx_node(const struct ssl_connection *peer, struct conn_ctx *conn)
{
	int ret;
	struct worker_pid *new;
	struct awaited_connection *aw;
	if (conn->flags & ENTRY_NODE) {
		uint8_t hash[SHA_DIGEST_LENGTH];
		/* FIXME */
		ret = update_routing_table_entry(&conn->ap, &conn->rte, server.port, NULL /**routing_certificate*/);
		if (ret != 0) {
			return -1;
		}
		SHA1(conn->ap.s6_addr, sizeof (conn->ap.s6_addr), hash);
		aw = register_wait_connection_permanent(NULL, hash);
		if (aw == NULL) {
			return -1;
		}
		while (1) {
			struct entry_worker *ew;
			{
				char buf[100];
				printf("awaiting incoming conn for %s\n", inet_ntop(AF_INET6, &conn->ap, buf, 100));
			}
			sem_post(&aw->entry_ok);
			ret = wait_for_connection(aw, LONG_TMOUT);
			printf("after wait\n");
			if (ret != 0) {
				free_awaited_connection(aw);
				return -1;
			}
			assert(aw->incoming_conn);
			ew = prepare_entry_worker(conn, peer, aw->incoming_conn);
			if (ew == NULL) {
				free_awaited_connection(aw);
				return -1;
			}
			new = malloc(sizeof (struct worker_pid));
			if (new == NULL) {
				free_awaited_connection(aw);
				free_entry_worker(ew);
				return -1;
			}
			pthread_mutex_lock(&server.worker_pid_mutex);
			LIST_insert(&server.pid_list, new);
			ret = pthread_create(&new->worker_pid, &ew->attr, (void *(*)(void *)) entry_worker, ew);
			pthread_mutex_unlock(&server.worker_pid_mutex);
			if (ret != 0) {
				free_awaited_connection(aw);
				free_entry_worker(ew);
				return -1;
			}
			/*cleanup_aw:*/
			if (aw->ip != NULL) {
				free(aw->ip);
				aw->ip = NULL;
			}
			if (aw->incoming_package != NULL) {
				free(aw->incoming_package);
				aw->incoming_package = NULL;
			}
			aw->incoming_conn = calloc(1, sizeof (struct ssl_connection));
			if (aw->incoming_conn == NULL) {
				free_awaited_connection(aw);
				return -1;
			}
		}
	} else { /* EXIT_NODE */
		while (1) {
			struct exit_worker *ew;
			uint8_t tunnel_dummy_package[TUNNEL_BLOCK_SIZE];
			struct tunnel_dummy_package *dp;
			ret = ssl_read(peer->ssl, tunnel_dummy_package, TUNNEL_BLOCK_SIZE);
			if (ret != 0) {
				if (server.quit) {
					return 0;
				}
				return -1;
			}
			dp = create_tunnel_dummy_package(tunnel_dummy_package, conn);
			if (dp == NULL) {
				return -1;
			}
			ew = prepare_exit_worker(dp, conn, peer);
			if (ew == NULL) {
				free(dp);
				return -1;
			}

			new = malloc(sizeof (struct worker_pid));
			if (new == NULL) {
				free_exit_worker(ew);
				return -1;
			}
			if (ew->reserve_ap) {
				return exit_worker(ew);
			}
			pthread_mutex_lock(&server.worker_pid_mutex);
			LIST_insert(&server.pid_list, new);
			ret = pthread_create(&new->worker_pid, &ew->attr, (void *(*)(void *)) exit_worker, ew);
			pthread_mutex_unlock(&server.worker_pid_mutex);
			if (ret != 0) {
				free_exit_worker(ew);
				return -1;
			}
		}
	}
}

static struct tunnel_worker *
prepare_tunnel_worker(struct awaited_connection *aw, X509 *awaited_cert, struct tunnel_dummy_package *dp, const struct conn_ctx *conn, const struct ssl_connection *peer)
{
	int ret;
	struct tunnel_worker *tw = calloc(sizeof (struct tunnel_worker), 1);
	if (tw == NULL) {
		return NULL;
	}
	ret = pthread_attr_init(&tw->attr);
	if (ret != 0) {
		free(tw);
		return NULL;
	}
	tw->awaited_cert = awaited_cert;
	tw->aw = aw;
	tw->peer = peer;
	tw->dp = dp;
	tw->conn = conn;
	return tw;
}

static void
free_tunnel_worker(struct tunnel_worker *tw)
{
	pthread_attr_destroy(&tw->attr);
	if (tw->aw != NULL) {
		free_awaited_connection(tw->aw);
	}
	if (tw->dp != NULL) {
		free(tw->dp);
	}
	free(tw);
}

static int
tunnel_worker(struct tunnel_worker *tw)
{
	int ret;
	uint8_t buf[4];
	socklen_t peer_len;
	uint8_t *init_package, *dummy_package, *init_reply_package, *success_package;
	struct sockaddr_in sa;
	struct ssl_connection *tunnel_conn;
	char *ip;
	peer_len = sizeof (sa);
	ret = wait_for_connection(tw->aw, TMOUT);
	if (ret != 0) {
		free_tunnel_worker(tw);
		return -1;
	}
	/* XXX this should have some sort of timeout */
	/* awaited connection has come */
	if (! X509_compare(tw->aw->incoming_conn->peer_cert, tw->awaited_cert)) {
		free_tunnel_worker(tw);
		return -1;
	}
	dummy_package = decrypt_tunnel_block(tw->dp, tw->aw->incoming_package + SHA_DIGEST_LENGTH);
	if (dummy_package == NULL) {
		free_tunnel_worker(tw);
		return -1;
	}
	if (memcmp(tw->dp->original_dummy, dummy_package, TUNNEL_BLOCK_SIZE)) {
		free(dummy_package);
		free_tunnel_worker(tw);
		return -1;
	}
	free(dummy_package);
	init_package = decrypt_tunnel_block(tw->dp, tw->aw->incoming_package + TUNNEL_BLOCK_SIZE + SHA_DIGEST_LENGTH);
	if (init_package == NULL) {
		free_tunnel_worker(tw);
		return -1;
	}
	ret = getpeername(tw->peer->socket, (struct sockaddr *) &sa, &peer_len);
	if (ret != 0) {
		free_tunnel_worker(tw);
		free(init_package);
		return -1;
	}
	ip = ip4_to_char(sa.sin_addr.s_addr);
	tunnel_conn = create_ssl_connection(ip, /*htons(sa.sin_port)*/ 8080, server.certificate, server.privkey);
	free(ip);
	if (tunnel_conn == NULL) {
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	if (! X509_compare(tunnel_conn->peer_cert, tw->peer->peer_cert)) {
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	serialize_32_t(2 * TUNNEL_BLOCK_SIZE + SHA_DIGEST_LENGTH, buf);
	ret = ssl_write(tunnel_conn->ssl, buf, 4);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, tw->peer_id, SHA_DIGEST_LENGTH);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, tw->dp->original_dummy, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, init_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	ret = ssl_read(tunnel_conn->ssl, init_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(init_package);
		free_tunnel_worker(tw);
		return -1;
	}
	init_reply_package = decrypt_tunnel_block(tw->dp, init_package);
	free(init_package);
	if (init_reply_package == NULL) {
		free_ssl_connection(tunnel_conn);
		free_tunnel_worker(tw);
		return -1;
	}
	ret = ssl_write(tw->aw->incoming_conn->ssl, init_reply_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free_tunnel_worker(tw);
		return -1;
	}
	/* send back package to anonymized node to tell him connection was
	 * sucessful */
	ret = ssl_read(tw->aw->incoming_conn->ssl, init_reply_package, TUNNEL_BLOCK_SIZE);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free(init_reply_package);
		free_tunnel_worker(tw);
		return -1;
	}
	success_package = decrypt_tunnel_block(tw->dp, init_reply_package);
	free(init_reply_package);
	if (success_package == NULL) {
		free_ssl_connection(tunnel_conn);
		free_tunnel_worker(tw);
		return -1;
	}
	ret = ssl_write(tunnel_conn->ssl, success_package, TUNNEL_BLOCK_SIZE);
	free(success_package);
	if (ret != 0) {
		free_ssl_connection(tunnel_conn);
		free_tunnel_worker(tw);
		return -1;
	}
	forward_traffic(tw->dp->key, tw->dp->iv, tw->aw->incoming_conn->ssl, tunnel_conn->ssl);
	free_ssl_connection(tunnel_conn);
	free_tunnel_worker(tw);
	return 0;
}

struct wfti_data {
	pthread_t tid;
	uint8_t tunnel_dummy_package[TUNNEL_BLOCK_SIZE];
	struct ssl_connection *conn;
	int got_it;
	sem_t *sem;
};

static int
wait_for_tunnel_init_package(struct wfti_data *d)
{
	int ret;
	assert(! pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL));
	ret = ssl_read(d->conn->ssl, d->tunnel_dummy_package, sizeof (d->tunnel_dummy_package));
	if (ret != 0) {
		d->got_it = -1;
		sem_post(d->sem);
		return -1;
	}
	d->got_it = 1;
	sem_post(d->sem);
	return 0;
}

static int
become_x_node(struct conn_ctx *conn, struct awaited_connection *x_conn)
{
	int ret;
	uint8_t zero[SHA_DIGEST_LENGTH];
	struct wfti_data one, two;
	struct awaited_connection *aw;
	struct tunnel_worker *tw;
	struct tunnel_dummy_package *dp;
	uint8_t *tunnel_dummy_package;
	struct worker_pid *new;
	sem_t sem;
	/* wait for x_package */
	ret = wait_for_connection(x_conn, TMOUT);
	if (ret != 0) {
		return -1;
	}
	if (! X509_compare(x_conn->incoming_conn->peer_cert, conn->prev_communication_certificate)) {
		return -1;
	}
	/* terminating x node */
	if (conn->flags & T_NODE) {
		bzero(zero, SHA_DIGEST_LENGTH);
		if (strcmp(conn->next_ip, "") && memcmp(conn->next_id, zero, SHA_DIGEST_LENGTH)) {
			ret = pass_x_package_on(conn);
			if (ret != 0) {
				printf("passing a x package on has failed\n");
				free_awaited_connection(x_conn);
				return -1;
			}
			conn->peer_id = conn->next_id;
			conn->peer_ip = conn->next_ip;
			conn->peer_cert = conn->next_communication_certificate;
			ret = become_tx_node(conn->to_next, conn);
		} else {
			conn->peer_id = conn->prev_id;
			conn->peer_ip = conn->prev_ip;
			conn->peer_cert = conn->prev_communication_certificate;
			ret = become_tx_node(x_conn->incoming_conn, conn);
		}
		return ret;
	}
	/* normal x node */
	ret = pass_x_package_on(conn);
	if (ret != 0) {
		printf("passing a x package on has failed\n");
		return -1;
	}
	while (1) {
		sem_init(&sem, 0, 0);
		one.conn = x_conn->incoming_conn;
		two.conn = conn->to_next;
		one.sem = &sem;
		two.sem = &sem;
		one.got_it = 0;
		two.got_it = 0;
		ret = pthread_create(&one.tid, NULL, (void *(*)(void *)) wait_for_tunnel_init_package, &one);
		if (ret != 0) {
			return -1;
		}
		ret = pthread_create(&two.tid, NULL, (void *(*)(void *)) wait_for_tunnel_init_package, &two);
		if (ret != 0) {
			return -1;
		}
		ret = sem_wait(&sem);
		if (ret != 0) {
			return -1;
		}
		ret = pthread_cancel((one.got_it)? two.tid : one.tid);
		if (ret != 0) {
			/*might be a problem since the not cancelled thread may
			 * write on our stackframe.... */
			return -1;
		}
		pthread_join(one.tid, NULL);
		pthread_join(two.tid, NULL);
		sem_destroy(&sem);
		if (one.got_it == -1 || two.got_it == -1) {
			return -1;
		}
		assert((one.got_it || two.got_it) && ! (one.got_it && two.got_it));
		tunnel_dummy_package = (one.got_it)? one.tunnel_dummy_package : two.tunnel_dummy_package;
		/* forward tunnel_packages that was received via poll calls */
		dp = create_tunnel_dummy_package(tunnel_dummy_package, conn);
		if (dp == NULL) {
			return -1;
		}
		if (tunnel_dummy_package == one.tunnel_dummy_package) {
			aw = register_wait_connection(conn->next_ip, conn->next_id);
		} else {
			aw = register_wait_connection(conn->prev_ip, conn->prev_id);
		}
		if (aw == NULL) {
			free(dp);
			return -1;
		}
		if (tunnel_dummy_package == one.tunnel_dummy_package) {
			ret = ssl_write(two.conn->ssl, dp->package, TUNNEL_BLOCK_SIZE);
		} else  {
			ret = ssl_write(one.conn->ssl, dp->package, TUNNEL_BLOCK_SIZE);
		}
		if (ret != 0) {
			free(dp);
			free_awaited_connection(aw);
			return -1;
		}
		/* start tunnel worker thread who awaits incoming connection */
		if (tunnel_dummy_package == one.tunnel_dummy_package) {
			tw = prepare_tunnel_worker(aw, conn->next_communication_certificate, dp, conn, x_conn->incoming_conn);
			tw->peer_id = conn->prev_id;
		} else {
			tw = prepare_tunnel_worker(aw, conn->prev_communication_certificate, dp, conn, conn->to_next);
			tw->peer_id = conn->next_id;
		}
		if (tw == NULL) {
			free(dp);
			free_awaited_connection(aw);
			return -1;
		}
		new = malloc(sizeof (struct worker_pid));
		if (new == NULL) {
			free_tunnel_worker(tw);
			return -1;
		}
		pthread_mutex_lock(&server.worker_pid_mutex);
		LIST_insert(&server.pid_list, new);
		ret = pthread_create(&new->worker_pid, &tw->attr, (void * (*)(void *)) tunnel_worker, tw);
		pthread_mutex_unlock(&server.worker_pid_mutex);
		if (ret != 0) {
			free_tunnel_worker(tw);
			return -1;
		}
	}
}

static int
check_for_kademlia_magic(SSL *ssl, X509 *client_cert, uint8_t *package, int size)
{
	int ret;
	assert(package);
	if (size < 4) {
		return -1;
	}
	switch (deserialize_32_t(package)) {
		case KAD_MAGIC_STORE:
			ret = handle_rpc_store(ssl, client_cert, package + 4, size - 4);
			break;
		case KAD_MAGIC_FIND_VALUE:
			ret = handle_rpc_find_value(ssl, client_cert, package + 4, size - 4);
			break;
		case KAD_MAGIC_FIND_NODE:
			ret = handle_rpc_find_node(ssl, client_cert, package + 4, size - 4);
			break;
		default:
			ret = -1;
			break;
	}
	return ret;
}

static int
worker(struct worker_data *wd)
{
	BIO *sock;
	int ret, was_awaited;
	uint32_t outsize;
	SSL *ssl;
	struct awaited_connection *help1, *help2, *aw;
	uint8_t *package;
	struct conn_ctx *fst, *snd;
	char *ip;
	ssl = SSL_new(server.ctx);
	if (ssl == NULL) {
		free(wd);
		return -1;
	}
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	sock = BIO_new_socket(wd->socket, BIO_CLOSE);
	if (sock == NULL) {
		SSL_free(ssl);
		free(wd);
		return -1;
	}
	SSL_set_bio(ssl, sock, sock);
	SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	ret = SSL_accept(ssl);
	if (ret != 1) {
		SSL_free(ssl);
		free(wd);
		return -1;
	}
	wd->client_cert = SSL_get_peer_certificate(ssl);
	if (wd->client_cert == NULL) {
		SSL_free(ssl);
		free_worker_data(wd);
		return -1;
	}
	package = read_package(ssl, &outsize);
	if (package == NULL) {
		SSL_free(ssl);
		free_worker_data(wd);
		return -1;
	}
	if (server.kad_running) {
		ret = check_for_kademlia_magic(ssl, wd->client_cert, package, outsize);
		if (ret == 0) {
			/* valid kademlia message found and handled - quit thread */
			free(package);
			SSL_free(ssl);
			free_worker_data(wd);
			return 0;
		} /* not a kademlia package */
	}
	if (outsize < SHA_DIGEST_LENGTH) {
		free(package);
		SSL_free(ssl);
		free_worker_data(wd);
		return -1;
	}
	was_awaited = 0;
	ip = parse_ip4_to_char(&wd->ip.sin_addr);
	if (ip == NULL) {
		free(package);
		SSL_free(ssl);
		free_worker_data(wd);
		return -1;
	}
	pthread_mutex_lock(&server.awaited_mutex);
	LIST_for_all(&server.awaited_list, help1, help2) {
		if (!memcmp(help1->id, package, SHA_DIGEST_LENGTH)) {
			if (help1->ip == NULL || !strcmp(help1->ip, ip)) {
				if (help1->permanent) {
					sem_wait(&help1->entry_ok);
				}
				help1->incoming_package = package;
				help1->incoming_conn->ssl = ssl;
				help1->incoming_conn->socket = wd->socket;
				help1->incoming_conn->peer_cert = wd->client_cert;
				help1->len = outsize;
				wd->client_cert = NULL;
				wd->socket = -1;
				if (! help1->permanent) {
					LIST_remove(help1);
				}
				sem_post(&help1->sem);
				was_awaited = 1;
				break;
			}
		}
	}
	pthread_mutex_unlock(&server.awaited_mutex);
	free(ip);
	if (was_awaited) {
		/* a thread waiting for this package is running */
		free_worker_data(wd);
		return -1;
	}
	fst = handle_first_package(wd, package, outsize);
	free(package);
	if (fst == NULL) {
		free_worker_data(wd);
		printf("got a package that was not a first round package\n");
		SSL_free(ssl);
		return -1;
	}
	package = read_package(ssl, &outsize);
	if (package == NULL) {
		printf("failed to receive snd package\n");
		free_worker_data(wd);
		free_conn_ctx(fst);
		SSL_free(ssl);
		return -1;
	}
	if (outsize < SHA_DIGEST_LENGTH) {
		free_conn_ctx(fst);
		SSL_free(ssl);
		free_worker_data(wd);
		return -1;
	}
	snd = handle_snd_package(package, outsize, fst, &aw);
	free_conn_ctx(fst);
	free(package);
	if (snd == NULL) {
		printf("handling a second round package failed\n");
		SSL_free(ssl);
		free_worker_data(wd);
		return -1;
	}
	if (snd->flags & X_NODE) {
		ret = become_x_node(snd, aw);
		free_conn_ctx(snd);
		free_worker_data(wd);
		free_awaited_connection(aw);
		SSL_free(ssl);
		return ret;
	} else { /* Y nodes are done now */
		free_worker_data(wd);
		free_conn_ctx(snd);
		SSL_free(ssl);
		return 0;
	}
}

static void
dummy(void *a)
{
	(void) a;
}

static int
mainloop(void)
{
	int sd, ret;
	socklen_t client_len;
	struct sockaddr_in sa_cli;
	struct worker_data *wd;
	struct thread_pool *t;
	client_len = sizeof (sa_cli);

	t = new_thread_pool(100);
	if (t == NULL) {
		printf("thread quitting 1\n");
		return -1;
	}
	while (1) {
		do {
			errno = 0;
			sd = accept(server.listen_sd, (struct sockaddr *) &sa_cli, &client_len);
		} while (errno == EINTR && !server.quit);
		if (server.quit) {
			free_thread_pool(t);
			return 0;
		}
		assert(sd != -1);
		wd = calloc(sizeof (struct worker_data), 1);
		if (wd == NULL) {
			free_thread_pool(t);
			printf("thread quitting 2\n");
			return -1;
		}
		wd->ip = sa_cli;
		wd->socket = sd;
		ret = thread_pool_dispatch(t, wd, dummy, (void (*)(void *)) worker);
		if (ret) {
			free_thread_pool(t);
			free_worker_data(wd);
			printf("thread quitting 4\n");
			perror(NULL);
			return -1;
		}
	}
}

static void
server_sigusr1_handler(int signo)
{
	(void) signo;
}

int
start_server(const struct config *config)
{
	int ret;
	struct sockaddr_in sa_serv;
	int optval;
	struct sigaction action;
	server.quit = 0;
	server.kad_running = 0;
	bzero(&action, sizeof(struct sigaction));
	ret = sigemptyset(&action.sa_mask);
	if (ret != 0) {
		return -1;
	}
	action.sa_handler = server_sigusr1_handler;
	ret = sigaction(SIGUSR1, &action, NULL);
	if (ret != 0) {
		return -1;
	}
	server.certificate = config->communication_certificate;
	server.config = config;
	server.privkey = config->private_communication_key;
	server.port = config->port;
	server.ip = config->ip;
	pthread_mutex_init(&server.awaited_mutex, NULL);
	pthread_mutex_init(&server.worker_pid_mutex, NULL);
	LIST_init(&server.awaited_list);
	LIST_init(&server.pid_list);
	server.ctx = SSL_CTX_new(SSLv23_server_method());
	if (server.ctx == 0) {
		return -1;
	}
	SSL_CTX_set_mode(server.ctx, SSL_MODE_AUTO_RETRY);
	ret = SSL_CTX_use_certificate(server.ctx, server.certificate);
	if (ret <= 0) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	ret = SSL_CTX_use_PrivateKey(server.ctx, server.privkey);
	if (ret <= 0) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	if (!SSL_CTX_check_private_key(server.ctx)) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	SSL_CTX_set_session_cache_mode(server.ctx, SSL_SESS_CACHE_OFF);
	server.listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (server.listen_sd == -1) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	optval = 1;
	ret = setsockopt(server.listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));
	if (ret == -1) {
		return -1;
	}
	bzero(&sa_serv, sizeof (sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(server.port);
	ret = bind(server.listen_sd, (struct sockaddr *) &sa_serv,
		   sizeof (sa_serv));
	if (ret == -1) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	ret = listen(server.listen_sd, 128);
	if (ret == -1) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	server.init = 1;
	ret = pthread_create(&(server.thread), NULL, (void *(*)(void *)) mainloop, NULL);
	if (ret) {
		SSL_CTX_free(server.ctx);
		return -1;
	}
	return 0;
}

void
stop_server(void)
{
	int ret;
	struct worker_pid *help1, *help2;
	assert(server.init && !server.quit);
	printf("asking server to terminate\n");
	server.quit = 1;
	pthread_kill(server.thread, SIGUSR1);
	ret = pthread_join(server.thread, NULL);
	if (ret != 0) {
		printf("failed to stop server properly\n");
		return;
	}
	LIST_for_all(&server.pid_list, help1, help2) {
		pthread_kill(help1->worker_pid, SIGUSR1);
		if (ret != 0) {
			printf("failed to stop server properly2\n");
			return;
		}
		pthread_join(help1->worker_pid, NULL);
	}
	LIST_clear(&server.pid_list, help1);
	SSL_CTX_free(server.ctx);
	close(server.listen_sd);
	printf("server exited\n");
}

void
kad_running(void)
{
	server.kad_running = 1;
}

void
not_kad_running(void)
{
	server.kad_running = 0;
}
