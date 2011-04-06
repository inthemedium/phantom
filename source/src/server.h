#ifndef __HAVE_SERVER_H__
#define __HAVE_SERVER_H__

#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <semaphore.h>
#include <inttypes.h>
#include <errno.h>
#include <poll.h>
#include <strings.h>
#include <sys/time.h>
#include "helper.h"
#include "conn_ctx.h"
#include "config.h"
#include "list.h"
#include "netdb.h"
#include "tunnel.h"
#include "kademlia_rpc.h"
#include "thread_pool.h"

#define TMOUT 120
#define LONG_TMOUT (60 * 60 * 24)

struct awaited_connection {
	struct awaited_connection *next;
	struct awaited_connection *prev;
	uint8_t id[SHA_DIGEST_LENGTH];
	int permanent;
	char *ip;
	sem_t sem;
	sem_t entry_ok;
	struct ssl_connection *incoming_conn;
	uint8_t *incoming_package;
	uint32_t len;
	struct timespec timeout;
};

struct worker_data {
	struct worker_data *next;
	struct worker_data *prev;
	int socket;
	struct sockaddr_in ip;
	X509 *client_cert;
};

struct tunnel_worker {
	pthread_attr_t attr;
	struct awaited_connection *aw;
	struct tunnel_dummy_package *dp;
	const struct ssl_connection *peer;
	const struct conn_ctx *conn;
	const uint8_t *peer_id;
	X509 *awaited_cert;
};

struct exit_worker {
	int reserve_ap;
	pthread_attr_t attr;
	const struct conn_ctx *conn;
	const struct ssl_connection *peer;
	const struct ssl_connection *incoming;
	struct tunnel_dummy_package *dp;
};

struct entry_worker {
	pthread_attr_t attr;
	const struct conn_ctx *conn;
	const struct ssl_connection *peer;
	struct ssl_connection *incoming_conn;
};

struct worker_pid {
	struct worker_pid *prev;
	struct worker_pid *next;
	pthread_t worker_pid;
};

struct server {
	struct worker_pid pid_list;
	struct awaited_connection awaited_list;
	pthread_mutex_t awaited_mutex;
	pthread_mutex_t worker_pid_mutex;
	const struct config *config;
	int init;
	int quit;
	int kad_running;
	uint16_t port;
	const char *ip;
	pthread_t thread;
	int listen_sd;
	SSL_CTX *ctx;
	X509 *certificate;
	EVP_PKEY *privkey;
};

int start_server(const struct config *config);
void stop_server(void);
struct awaited_connection *register_wait_connection(const char *ip, const uint8_t *id);
int wait_for_connection(struct awaited_connection *w, int timeout);
void free_awaited_connection(struct awaited_connection *w);
void kad_running(void);
void not_kad_running(void);

#endif
