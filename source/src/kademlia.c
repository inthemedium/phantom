#include "kademlia.h"
#include "kademlia_rpc.h"
#include "kad_contacts.h"

static struct kad *kad = NULL;

static void __attribute__((unused))
dump_kad_node_info(struct kad_node_info *node)
{
	hexdump(node->id, SHA_DIGEST_LENGTH);
	printf("\nport: %hi,ip: %s\n", node->port, node->ip);
}

static struct kad_node_list *
new_kad_node_list(void)
{
	struct kad_node_list *r;
	r = malloc(sizeof (struct kad_node_list));
	if (r == NULL) {
		return r;
	}
	r->nentries = 0;
	LIST_init(&r->list);
	return r;
}

void
free_kad_node_list(struct kad_node_list *l)
{
	struct kad_node_info *help1, *help2;
	if (l == NULL) {
		return;
	}
	LIST_for_all(&l->list, help1, help2) {
		LIST_remove(help1);
		free_kad_node_info(help1);
	}
	free(l);
}

static void
distance(const uint8_t *id1, const uint8_t *id2, uint8_t *out)
{
	int i;
	assert(id1 && id2 && out);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		out[i] = id1[i] ^ id2[i];
	}
}

static int
bucket_idx(const uint8_t *id)
{
	/* binary - do you speak it? */
	int r, tmp, i;
#define __LT(n) n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n
	static const uint8_t logs[0xff + 1] = {
		-1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
		__LT(4), __LT(5), __LT(5), __LT(6), __LT(6), __LT(6), __LT(6),
		__LT(7), __LT(7), __LT(7), __LT(7), __LT(7), __LT(7), __LT(7),
		__LT(7)
	};
	assert(kad);
	assert(id);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		if (! (tmp = id[i] ^ kad->own_id[i])) {
			continue;
		}
		r = logs[tmp];
		r = NBUCKETS - ((i + 1) * 8) + r;
		assert(r > -1 && r < NBUCKETS);
		return r;
	}
	assert(!memcmp(id, kad->own_id, SHA_DIGEST_LENGTH));
	return -1;
}

static struct ping_nodes *
new_ping_nodes(void)
{
	int ret;
	struct ping_nodes *p = malloc(sizeof (struct ping_nodes));
	if (p == NULL) {
		return NULL;
	}
	LIST_init(&p->list);
	pthread_mutex_init(&p->lock, NULL);
	ret = sem_init(&p->sem, 0, 0);
	if (ret != 0) {
		free(p);
		return NULL;
	}
	return p;
}

static void
free_ping_nodes(struct ping_nodes *p)
{
	struct kad_node_info *help1, *help2;
	assert(p);
	pthread_mutex_lock(&p->lock);
	LIST_for_all(&p->list, help1, help2) {
		LIST_remove(help1);
		free_kad_node_info(help1);
	}
	pthread_mutex_unlock(&p->lock);
	assert( !pthread_mutex_destroy(&p->lock));
	sem_destroy(&p->sem);
	free(p);
}

static struct kad_table *
new_kad_table(void)
{
	int i;
	struct kad_table *t = malloc(sizeof (struct kad_table));
	if (t == NULL) {
		return NULL;
	}
	for (i = 0; i < NBUCKETS; i++) {
		pthread_mutex_init(&t->bucket_mutexes[i], NULL);
		LIST_init(&t->buckets[i]);
		t->entries[i] = 0;
		t->last_action[i].tv_sec = 0;
	}
	return t;
}

static void
free_kad_table(struct kad_table *t)
{
	int i;
	struct kad_node_info *help1, *help2;
	assert(t);
	for (i = 0; i < NBUCKETS; i++) {
		pthread_mutex_lock(&t->bucket_mutexes[i]);
		LIST_for_all(&t->buckets[i], help1, help2) {
			LIST_remove(help1);
			free_kad_node_info(help1);
		}
		pthread_mutex_unlock(&t->bucket_mutexes[i]);
		assert(! pthread_mutex_destroy(&t->bucket_mutexes[i]));
	}
	free(t);
}

static void
timestamp(struct kad_node_info *n)
{
	/* should never fail if used right */
	assert(n);
	assert(! clock_gettime(CLOCK_REALTIME, &n->last_seen));
}

static void
ping_enqueue(struct kad_node_info *n)
{
	assert(n);
	pthread_mutex_lock(&kad->ping->lock);
	LIST_insert_before(&kad->ping->list, n);
	pthread_mutex_unlock(&kad->ping->lock);
	sem_post(&kad->ping->sem);
}

static struct kad_node_info *
ping_deqeue(void)
{
	struct kad_node_info *n;
	struct timespec to;
	int ret;
again:
	assert( !clock_gettime(CLOCK_REALTIME, &to));
	to.tv_sec += CHECKQUITTIMEOUT;
	errno = 0;
	ret = sem_timedwait(&kad->ping->sem, &to);
	if (errno == ETIMEDOUT) {
		if (kad->quit) {
			return NULL;
		}
		goto again;
	}
	assert(ret == 0);
	pthread_mutex_lock(&kad->ping->lock);
	assert(! LIST_is_empty(&kad->ping->list));
	n = kad->ping->list.next;
	LIST_remove(n);
	pthread_mutex_unlock(&kad->ping->lock);
	assert(n);
	return n;
}

static void
update_worker(void)
{
	int idx, ret;
	struct kad_node_info *help1, *help2, *head;
	struct kad_node_info *node;
	struct timespec to;
	while (1) {
		assert( !clock_gettime(CLOCK_REALTIME, &to));
		to.tv_sec += CHECKQUITTIMEOUT;
		errno = 0;
		ret = sem_timedwait(&kad->updates.sem, &to);
		if (errno == ETIMEDOUT) {
			if (kad->quit) {
				pthread_mutex_lock(&kad->updates.mutex);
				LIST_for_all(&kad->updates.list, help1, help2) {
					LIST_remove(help1);
					free_kad_node_info(help1);
				}
				pthread_mutex_unlock(&kad->updates.mutex);
				return;
			}
			continue;
		}
		assert(ret == 0);
		pthread_mutex_lock(&kad->updates.mutex);
		node = kad->updates.list.next;
		LIST_remove(node);
		pthread_mutex_unlock(&kad->updates.mutex);
		assert(node && node->ip && node->cert && node->pbc);
		idx = bucket_idx(node->id);
		assert(idx != -1);
		pthread_mutex_lock(&kad->table->bucket_mutexes[idx]);
		LIST_for_all(&kad->table->buckets[idx], help1, help2) {
			if (! memcmp(node->id, help1->id, SHA_DIGEST_LENGTH)) {
				/* node already known */
				free_kad_node_info(node);
				LIST_remove(help1);
				timestamp(help1);
				LIST_insert_before(&kad->table->buckets[idx], help1);
				goto out;
			}
		} /* node not known */
		/*printf("new contact for bucket %d encountered with ip: %s\n", idx, node->ip);*/
		if (kad->table->entries[idx] < KADEMLIA_K) { /* bucket not full */
			LIST_insert_before(&kad->table->buckets[idx], node);
			kad->table->entries[idx]++;
			goto out;
		} else { /* bucket full */
			assert(kad->table->entries[idx] == KADEMLIA_K);
			head = kad->table->buckets[idx].next;
			LIST_remove(head);
			ping_enqueue(head);
			pthread_mutex_unlock(&kad->table->bucket_mutexes[idx]);
			sem_wait(&head->sem); /* this will return at some point due to ping timeout*/
			pthread_mutex_lock(&kad->table->bucket_mutexes[idx]);
			if (head->ponged) { /* keep old contact */
				free_kad_node_info(node);
				LIST_insert_before(&kad->table->buckets[idx], head);
			} else { /* keep new contact */
				free_kad_node_info(head);
				LIST_insert_before(&kad->table->buckets[idx], node);
			}
		}
out:
		clock_gettime(CLOCK_REALTIME, &kad->table->last_action[idx]);
		pthread_mutex_unlock(&kad->table->bucket_mutexes[idx]);
	}
}

static void
do_ping(struct kad_node_info *n)
{
	int ret;
	struct ssl_connection *c;
	uint8_t hash[SHA_DIGEST_LENGTH];
	assert(n);
	n->ponged = 0;
	c = create_ssl_connection_tmout(n->ip, n->port, kad->config->communication_certificate, kad->config->private_communication_key, PING_TIMEOUT);
	if (c == NULL) {
		return;
	}
	assert(c->peer_cert);
	ret = X509_hash(c->peer_cert, hash);
	free_ssl_connection(c);
	if (ret != 0) {
		return;
	}
	if (memcmp(hash, n->id, SHA_DIGEST_LENGTH)) {
		return;
	}
	n->ponged = 1;
	timestamp(n);
}

static void
ping_worker(void)
{
	struct kad_node_info *n;
	while (1) {
		n = ping_deqeue();
		if (n == NULL) {
			assert(kad->quit);
			return;
		}
		do_ping(n);
		sem_post(&n->sem);
	}
}

static struct kad_node_info *
kad_node_clone(const struct kad_node_info *n)
{
	assert(n);
	return new_kad_node_info(n->id, n->ip, n->port, n->cert, n->pbc);
}

static int
get_bucket_contents(struct kad_node_list *list, int idx, const uint8_t *except, int n)
{
	struct kad_node_info *help1, *help2, *node;
	assert(list);
	assert(idx < NBUCKETS && idx > -1);
	pthread_mutex_lock(&kad->table->bucket_mutexes[idx]);
	LIST_for_all(&kad->table->buckets[idx], help1, help2) {
		if (except && ! memcmp(help1->id, except, SHA_DIGEST_LENGTH)) {
			continue;
		}
		node = kad_node_clone(help1);
		assert(node->ip);
		if (node == NULL) {
			pthread_mutex_unlock(&kad->table->bucket_mutexes[idx]);
			return -1;
		}
		LIST_insert(&list->list, node);
		list->nentries++;
		if (list->nentries == n) {
			pthread_mutex_unlock(&kad->table->bucket_mutexes[idx]);
			return 0;
		}
	}
	pthread_mutex_unlock(&kad->table->bucket_mutexes[idx]);
	return 0;
}

static struct kad_node_list *
get_n_closest_nodes(int n, const uint8_t *id, const uint8_t *except)
{
	int idx, i, ret;
	struct kad_node_list *list;
	int tested[NBUCKETS];
	assert(id);
	idx = bucket_idx(id);
	list = new_kad_node_list();
	if (list == NULL) {
		return NULL;
	}
	if (idx == -1) {
		idx++;
	}
	bzero(tested, NBUCKETS * sizeof (int));
	for (i = idx; i < NBUCKETS; i++) {
		ret = get_bucket_contents(list, i, except, n);
		tested[i]++;
		if (ret != 0) {
			free_kad_node_list(list);
			return NULL;
		}
		if (list->nentries == n) {
			return list;
		}
	}
	for (i = 0; i < idx; i++) {
		ret = get_bucket_contents(list, i, except, n);
		tested[i]++;
		if (ret != 0) {
			free_kad_node_list(list);
			return NULL;
		}
		if (list->nentries == n) {
			return list;
		}
	}
	for (i = 0; i < NBUCKETS; i++) {
		if (tested[i] != 1) {
			printf("%d tested %d times\n", i, tested[i]);
		}
	}
	if (! list->nentries) {
		free_kad_node_list(list);
		return NULL;
	}
	return list;
}

static struct kad_node_info *
find_closest_node(const uint8_t *key, uint8_t *out, const struct kad_node_list *l)
{
	struct kad_node_info *help1, *help2, *nret;
	uint8_t dist[SHA_DIGEST_LENGTH];
	int ret;
	assert(key);
	assert(l);
	assert(l->nentries);
	if (out) {
		memcpy(out, l->list.next->id, SHA_DIGEST_LENGTH);
	}
	nret = l->list.next;
	LIST_for_all(&l->list, help1, help2) {
		assert(help1->ip);
		distance(key, help1->id, dist);
		ret = memcmp(nret->id, dist, SHA_DIGEST_LENGTH);
		if (ret > 0) { /* help1 is closer than previous closest */
			if (out) {
				memcpy(out, help1->id, SHA_DIGEST_LENGTH);
			}
			nret = help1;
		}
	}
	assert(nret);
	return nret;
}

struct poll_worker_data {
	uint8_t id[SHA_DIGEST_LENGTH];
	struct kad_node_info *n;
	struct rpc_return *ret;
};

static void
poll_find_node_worker(struct poll_worker_data *pwd)
{
	assert(pwd);
	assert(pwd->n);
	pwd->ret = rpc_find_node(pwd->id, pwd->n, kad->config->communication_certificate, kad->config->private_communication_key, &kad->self);
}

static void
poll_find_value_worker(struct poll_worker_data *pwd)
{
	assert(pwd);
	assert(pwd->n);
	pwd->ret = rpc_find_value(pwd->id, pwd->n, kad->config->communication_certificate, kad->config->private_communication_key, &kad->self);
}

static void __attribute__((unused))
dump_shortlist(struct kad_node_list *list)
{
	struct kad_node_info *help1, *help2;
	printf("list has %d entries\n", list->nentries);
	LIST_for_all(&list->list, help1, help2) {
		printf("%s\n", help1->ip);
	}
}

static void
random_id_for_bucket(int idx, uint8_t *buf)
{
	int i;
	assert(buf);
	assert(idx > -1 && idx < NBUCKETS);
	rand_bytes(buf, SHA_DIGEST_LENGTH);
	for (i = 0; i < (NBUCKETS - idx - 1) / 8; i++) {
		buf[i] = kad->own_id[i];
	}
	if (!idx % 8) {
		i++;
	}
	buf[i] = kad->own_id[i] ^ ((kad->own_id[i] ^ ~kad->own_id[i]) & (0x01 << (idx % 8)));
	assert(bucket_idx(buf) == idx);
}

static void
update_lists(struct kad_node_list *polled, struct kad_node_list *unpolled, struct kad_node_info *failed, struct poll_worker_data *pwd)
{
	int i, skip;
	struct kad_node_info *help1, *help2, *help3, *help4;
	assert(polled);
	assert(unpolled);
	assert(failed);
	assert(pwd);
	if (pwd->ret == NULL) {
		/* node failed to reply */
		LIST_insert(failed, pwd->n);
		LIST_for_all(failed, help1, help2) {
			LIST_for_all(&unpolled->list, help3, help4) {
				if (! memcmp(help1->id, help3->id, SHA_DIGEST_LENGTH)) {
					LIST_remove(help3);
					free_kad_node_info(help3);
					unpolled->nentries--;
					break;
				}
			}
		}
		return;
	}
	LIST_insert(&polled->list, pwd->n);
	polled->nentries++;
	LIST_for_all(&polled->list, help1, help2) {
		LIST_for_all(&unpolled->list, help3, help4) {
			if (! memcmp(help1->id, help3->id, SHA_DIGEST_LENGTH)) {
				LIST_remove(help3);
				free_kad_node_info(help3);
				unpolled->nentries--;
				break;
			}
		}
	}
	/* skip copies of our own node or already polled/failed nodes and do not add nodes to unpolled twice */
	for (i = 0; i < pwd->ret->nnodes; i++) {
		skip = 0;
		if (! memcmp(pwd->ret->nodes[i]->id, kad->own_id, SHA_DIGEST_LENGTH)) {
			skip = 1;
		} else {
			LIST_for_all(failed, help1, help2) {
				if (! memcmp(help1->id, pwd->ret->nodes[i]->id, SHA_DIGEST_LENGTH)) {
					skip = 1;
					break;
				}
			}
			if (! skip) {
				LIST_for_all(&polled->list, help1, help2) {
					if (! memcmp(help1->id, pwd->ret->nodes[i]->id, SHA_DIGEST_LENGTH)) {
						skip = 1;
						break;
					}
				}
			}
			if (!skip) {
				LIST_for_all(&unpolled->list, help1, help2) {
					if (! memcmp(help1->id, pwd->ret->nodes[i]->id, SHA_DIGEST_LENGTH)) {
						skip = 1;
						break;
					}
				}
			}
		}
		if (skip) {
			assert(skip == 1);
			continue;
		}
		/* copy rest of replied nodes to unpolled */
		LIST_insert(&unpolled->list, pwd->ret->nodes[i]);
		pwd->ret->nodes[i] = NULL;
		unpolled->nentries++;
	}
}

#if 0
static int
cmp_distance(const uint8_t *a, const uint8_t *b, const uint8_t *key)
{
	uint8_t to_a[SHA_DIGEST_LENGTH], to_b[SHA_DIGEST_LENGTH];
	distance(a, key, to_a);
	distance(b, key, to_b);
	return memcmp(to_a, to_b, SHA_DIGEST_LENGTH);
}

static struct kad_node_info *
mergesort(struct kad_node_info *l, const uint8_t *id)
{
	struct kad_node_info *p, *q, *e, *t, *oh;
	int ni, nm, np, nq, i;
	assert(l);
	ni = 1;
	while (1) {
		oh = l;
		p = l;
		nm = 0;
		t = NULL;
		l = NULL;
		while (p) {
			nm++;
			np = 0;
			q = p;
			for (i = 0; i < ni; i++) {
				np++;
				q = (q->next == oh) ? NULL : q->next;
				if (q == NULL) {
					break;
				}
			}
			nq = ni;
			while (np > 0 || (nq > 0 && q)) {
				if (np == 0) {
					e = q;
					q = q->next;
					nq--;
					if (q == oh) {
						q = NULL;
					}
				} else if (nq == 0 || q == NULL || cmp_distance(p->id, q->id, id) <= 0) {
					e = p;
					p = p->next;
					np--;
					if (p == oh) {
						p = NULL;
					}
				} else {
					e = q;
					q = q->next;
					nq--;
					if (q == oh) {
						q = NULL;
					}
				}
				if (t != NULL) {
					t->next = e;
				} else {
					l = e;
				}
				e->prev = t;
				t = e;
			}
			p = q;
		}
		t->next = l;
		l->prev = t;
		if (nm <= 1) {
			return l;
		}
		ni <<= 1;
	}
}

static void
sort_list_by_closeness(const uint8_t *id, struct kad_node_list *l)
{
	assert(l);
	assert(l->nentries);
	assert(id);
	l->list = *mergesort(&l->list, id);
}
#endif

static struct kad_node_list *
iterative_find(const uint8_t *id, uint8_t **data, size_t *len, int wantvalue)
{
	struct kad_node_list *polled, *unpolled;
	struct kad_node_info *help1, *help2, failed;
	int alpha, i, ret, got_it;
	struct poll_worker_data pwds[KADEMLIA_ALPHA];
	pthread_t tids[KADEMLIA_ALPHA];
	uint8_t closest_node[SHA_DIGEST_LENGTH];
	assert(id);
	if (wantvalue) {
		assert(data);
		assert(len);
	}
	unpolled = get_n_closest_nodes(KADEMLIA_ALPHA, id, NULL);
	if (unpolled == NULL) {
		return NULL;
	}
	polled = new_kad_node_list();
	if (polled == NULL) {
		free_kad_node_list(unpolled);
		return NULL;
	}
	LIST_init(&failed);
	assert(unpolled->nentries);
	find_closest_node(id, closest_node, unpolled);
	for (i = 0; i < KADEMLIA_ALPHA; i++) {
		memcpy(pwds[i].id, id, SHA_DIGEST_LENGTH);
	}
	got_it = 0;
	while (polled->nentries < KADEMLIA_K && unpolled->nentries) {
		/*sort_list_by_closeness(id, unpolled);*/
		alpha = (unpolled->nentries < KADEMLIA_ALPHA)? unpolled->nentries : KADEMLIA_ALPHA;
		i = 0;
		LIST_for_all(&unpolled->list, help1, help2) {
			if (i == alpha) {
				break;
			}
			LIST_remove(help1);
			assert(help1);
			unpolled->nentries--;
			pwds[i].n = help1;
			assert(memcmp(help1->id, kad->own_id, SHA_DIGEST_LENGTH));
			if (wantvalue) {
				ret = pthread_create(&tids[i], NULL, (void *(*)(void *)) poll_find_value_worker, &pwds[i]);
			} else {
				ret = pthread_create(&tids[i], NULL, (void *(*)(void *)) poll_find_node_worker, &pwds[i]);
			}
			if (ret != 0) {
				free_kad_node_list(unpolled);
				free_kad_node_list(polled);
				return NULL;
			}
			i++;
		}
		assert(i == alpha);
		for (i = 0; i < alpha; i++) {
			ret = pthread_join(tids[i], NULL);
			if (ret != 0) {
				free_kad_node_list(unpolled);
				free_kad_node_list(polled);
				return NULL;
			}
			if (wantvalue && ! got_it) {
				if (pwds[i].ret && pwds[i].ret->success) {
					*data = pwds[i].ret->data;
					pwds[i].ret->data = NULL;
					*len = pwds[i].ret->len;
					got_it = 1;
				}
			}
			update_lists(polled, unpolled, &failed, &pwds[i]);
			if (pwds[i].ret != NULL) {
				free_rpc_return(pwds[i].ret);
			}
		}
		if (got_it) {
			/* XXX post datum to nearest node who did not return it */
			free_kad_node_list(unpolled);
			free_kad_node_list(polled);
			LIST_for_all(&failed, help1, help2) {
				free_kad_node_info(help1);
			}
			return NULL;
		}
		if (polled->nentries) {
			find_closest_node(id, closest_node, polled);
		}
	}
	free_kad_node_list(unpolled);
	LIST_for_all(&failed, help1, help2) {
		free_kad_node_info(help1);
	}
	if (polled->nentries) {
		return polled;
	}
	free_kad_node_list(polled);
	return NULL;
}

static struct kad_node_list *
iterative_find_node(const uint8_t *id)
{
	return iterative_find(id, NULL, NULL, 0);
}

static void
house_keeping_worker(void)
{
	struct timespec t;
	int ret, i;
	uint8_t id[SHA_DIGEST_LENGTH];
	while (1) {
		poll(NULL, 0, 1000 * HOUSE_KEEPING_TIMEOUT);
		if (kad->quit) {
			return;
		}
		ret = clock_gettime(CLOCK_REALTIME, &t);
		assert(ret == 0);
		for (i = 1; i < NBUCKETS; i++) {
			if (t.tv_sec - kad->table->last_action[i].tv_sec > KAD_T_REFRESH) {
				random_id_for_bucket(i, id);
				free_kad_node_list(iterative_find_node(id));
				assert(! clock_gettime(CLOCK_REALTIME, &kad->table->last_action[i]));
				if (kad->quit) {
					return;
				}
			}
		}
		/* XXX republish data replicate data expire data */
	}
}

static int
join_network(const char *filename)
{
	struct kad_node_list *list;
	struct kad_node_info start_contacts, *help1, *help2;
	int ret, i;
	assert(filename);
	ret = restore_contacts(filename, &start_contacts);
	if (ret != 0) {
		return -1;
	}
	LIST_for_all(&start_contacts, help1, help2) {
		assert(help1->ip);
		assert(help1->port);
		assert(help1->id);
		assert(help1->cert);
		update_table_relay(help1);
		for (i = 0; i < MAX_JOIN_RETRIES; i++) {
			list = iterative_find_node(kad->own_id);
			if (list != NULL) {
				break;
			}
			poll(NULL, 0, 1000 * JOIN_WAIT);
		}
		if (list != NULL) {
			free_kad_node_list(list);
			LIST_for_all(&start_contacts, help1, help2) {
				free_kad_node_info(help1);
			}
			return 0;
		}
	}
	/* refresh all buckets -> start houekeeping thread */
	LIST_for_all(&start_contacts, help1, help2) {
		free_kad_node_info(help1);
	}
	return -1;
}

int
start_kad(const struct config *config)
{
	int ret;
	struct thread *thread;
	cleanup_stack_init;
	assert(config);
	assert(!kad);
	kad = calloc(1, sizeof(struct kad));
	if (kad == NULL) {
		return -1;
	}
	cleanup_stack_push(free, kad);
	kad->quit = 0;
	kad->config = config;
	kad->table = new_kad_table();
	if (kad->table == NULL) {
		kad = NULL;
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free_kad_table, kad->table);
	kad->cache = new_disk_cache(config->kad_data_dir);
	if (kad->cache == NULL) {
		kad = NULL;
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free_disk_cache, kad->cache);
	kad->ping = new_ping_nodes();
	if (kad->ping == NULL) {
		kad = NULL;
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free_ping_nodes, kad->ping);
	ret = X509_hash(config->communication_certificate, kad->own_id);
	if (ret != 0) {
		cleanup_stack_free_all();
		return -1;
	}
	pthread_mutex_init(&kad->updates.mutex, NULL);
	LIST_init(&kad->updates.list);
	ret = sem_init(&kad->updates.sem, 0, 0);
	if (ret != 0) {
		cleanup_stack_free_all();
		return -1;
	}
	node_info__init(&kad->self);
	kad->self.ip = config->ip;
	kad->self.port = config->port;
	kad->self.id.len = SHA_DIGEST_LENGTH;
	kad->self.id.data = kad->own_id;
	kad->self.cert.data = config->communication_certificate_flat->data;
	kad->self.cert.len = config->communication_certificate_flat->len;
	kad->self.pbc.data = config->construction_certificate_flat->data;
	kad->self.pbc.len = config->construction_certificate_flat->len;
	LIST_init(&kad->thread_list);
	thread = malloc(sizeof(struct thread));
	if (thread == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free, thread);
	ret = pthread_create(&thread->thread, NULL, (void *(*)(void *)) ping_worker, NULL);
	if (ret != 0) {
		cleanup_stack_free_all();
		return -1;
	}
	LIST_insert(&kad->thread_list, thread);
	thread = malloc(sizeof(struct thread));
	if (thread == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free, thread);
	ret = pthread_create(&thread->thread, NULL, (void *(*)(void *)) update_worker, NULL);
	if (ret != 0) {
		cleanup_stack_free_all();
		return -1;
	}
	LIST_insert(&kad->thread_list, thread);
	thread = malloc(sizeof(struct thread));
	if (thread == NULL) {
		cleanup_stack_free_all();
		return -1;
	}
	kad_running();
	ret = join_network(config->kad_node_file);
	if (ret != 0) {
		printf("Failed to join kademlia network\n");
		cleanup_stack_free_all();
		return -1;
	}
	cleanup_stack_push(free, thread);
	kad->nodefile = strdup(config->kad_node_file);
	if (kad->nodefile == NULL) {
		cleanup_stack_free_all();
		return -1;

	}
	cleanup_stack_push(free, kad->nodefile);
	/* start the house_keeping thread after joining the network - so the
	 * timevals will be initialized */
	ret = pthread_create(&thread->thread, NULL, (void *(*)(void *)) house_keeping_worker, NULL);
	if (ret != 0) {
		cleanup_stack_free_all();
		return -1;
	}
	LIST_insert(&kad->thread_list, thread);
	printf("Join to kad network was sucessful\n");
	return 0;
}

void
stop_kad(void)
{
	struct thread *help1, *help2;
	printf("stopping kademlia...\n");
	kad->quit = 1;
	not_kad_running();
	/*save_contacts(kad->nodefile, kad->table);*/
	LIST_for_all(&kad->thread_list, help1, help2) {
		pthread_join(help1->thread, NULL);
		free(help1);
	}
	free_disk_cache(kad->cache);
	free_kad_table(kad->table);
	free_ping_nodes(kad->ping);
	free(kad->nodefile);
	free(kad);
	kad = NULL;
	printf("kademlia stopped\n");
}

struct kad_node_info *
new_kad_node_info(const uint8_t *id, const char *ip, uint16_t port, X509 *cert, X509 *pbc)
{
	struct kad_node_info *n;
	int ret;
	assert(id);
	assert(ip);
	assert(cert);
	assert(pbc);
	n = malloc(sizeof (struct kad_node_info));
	if (n == NULL) {
		return NULL;
	}
	memcpy(n->id, id, SHA_DIGEST_LENGTH);
	n->ip = strdup(ip);
	if (n->ip == NULL) {
		free(n);
		return NULL;
	}
	n->port = port;
	n->cert = clone_cert(cert);
	if (n->cert == NULL) {
		free(n->ip);
		free(n);
		return NULL;
	}
	n->pbc = clone_cert(pbc);
	if (n->pbc == NULL) {
		X509_free(n->cert);
		free(n->ip);
		free(n);
		return NULL;
	}
	ret = sem_init(&n->sem, 0, 0);
	if (ret != 0) {
		X509_free(n->pbc);
		X509_free(n->cert);
		free(n->ip);
		free(n);
		return NULL;
	}
	return n;
}

void
free_kad_node_info(struct kad_node_info *n)
{
	assert(n);
	if (n->cert != NULL) {
		X509_free(n->cert);
	}
	if (n->pbc != NULL) {
		X509_free(n->pbc);
	}
	if (n->ip != NULL) {
		free(n->ip);
	}
	free(n);
}

void
update_table_relay(const struct kad_node_info *n)
{
	struct kad_node_info *node;
	assert(n);
	/*assert(memcmp(n->id, kad->own_id, SHA_DIGEST_LENGTH));*/
	if (! memcmp(n->id, kad->own_id, SHA_DIGEST_LENGTH)) {
		printf("id collission\n");
		return;
	}
	node = kad_node_clone(n);
	if (node == NULL) {
		printf("node clone fail\n");
		/*XXX we will miss an update here in the unlikely case of memory
		 * failure */
		return;
	}
	timestamp(node);
	pthread_mutex_lock(&kad->updates.mutex);
	LIST_insert_before(&kad->updates.list, node);
	pthread_mutex_unlock(&kad->updates.mutex);
	sem_post(&kad->updates.sem);
}

static struct kad_node_list *
iterative_find_value(const uint8_t *id, uint8_t **data, size_t *len)
{
	struct kad_node_list *ret;
	assert(id);
	assert(data);
	assert(len);
	*data = disk_cache_find(kad->cache, id, len);
	if (*data != NULL) {
		assert(*len);
		return NULL;
	}
	ret = iterative_find(id, data, len, 1);
	if (*data != NULL) {
		assert(*len);
		assert(ret == NULL);
		return NULL;
	}
	return ret;
}

int
local_find(const uint8_t *key, uint8_t **data, size_t *len)
{
	assert(key);
	assert(data);
	assert(len);
	*data = disk_cache_find(kad->cache, key, len);
	if (*data != NULL) {
		assert(*len);
		return 0;
	}
	return -1;
}

int
kad_store(uint8_t *key, uint8_t *data, uint32_t len)
{
	struct kad_node_list *list;
	struct kad_node_info *help1, *help2;
	int cnt, ret;
	assert(key);
	assert(data);
	assert(len);
	list = iterative_find_node(key);
	if (list == NULL) {
		return -1;
	}
	cnt = 0;
	LIST_for_all(&list->list, help1, help2) {
		ret = rpc_store(key, data, len, help1, kad->config->communication_certificate, kad->config->private_communication_key, &kad->self);
		if (ret == -1) {
			continue;
		}
		cnt++;
	}
	free_kad_node_list(list);
	return (cnt > 0)? cnt : -1;
}

int
local_store(const uint8_t *key, const uint8_t *data, uint32_t len)
{
	assert(key);
	assert(data);
	return disk_cache_store(kad->cache, key, data, len);
}

struct kad_node_list *
get_k_closest_nodes(const uint8_t *id, const uint8_t *requestor)
{
	assert(id);
	assert(requestor);
	return get_n_closest_nodes(KADEMLIA_K, id, requestor);
}

struct kad_node_list *
get_n_nodes(int n)
{
	int i;
	struct kad_node_info *help1, *help2, *node;
	struct kad_node_list *list;
	list = new_kad_node_list();
	if (list == NULL) {
		return NULL;
	}
	for (i = NBUCKETS - 1; i >= 0; i--) {
		pthread_mutex_lock(&kad->table->bucket_mutexes[i]);
		LIST_for_all(&kad->table->buckets[i], help1, help2) {
			node = kad_node_clone(help1);
			if (node == NULL) {
				free_kad_node_list(list);
				pthread_mutex_unlock(&kad->table->bucket_mutexes[i]);
				return NULL;
			}
			assert(node->ip);
			assert(node->port);
			assert(node->cert);
			assert(node->pbc);
			LIST_insert(&list->list, node);
			list->nentries++;
			if (list->nentries == n) {
				pthread_mutex_unlock(&kad->table->bucket_mutexes[i]);
				return list;
			}
		}
		pthread_mutex_unlock(&kad->table->bucket_mutexes[i]);
	}
	free_kad_node_list(list);
	return NULL;
}

int kad_find(const uint8_t *key, uint8_t **data, size_t *len)
{
	struct kad_node_list *list;
	assert(key);
	assert(data);
	assert(len);
	*data = NULL;
	list = iterative_find_value(key, data, len);
	if (list == NULL) {
		if (*data != NULL) {
			assert(*len);
			return 0;
		}
	} else {
		assert(*data == NULL);
		free_kad_node_list(list);
	}
	return -1;
}

void
get_free_ap_adress(struct in6_addr *ap)
{
	static uint8_t ap_prefix[] = AP_PREFIX;
	assert(sizeof (ap_prefix) < sizeof (ap->s6_addr));
	memcpy(ap->s6_addr, ap_prefix, sizeof (ap_prefix));
	rand_bytes(ap->s6_addr + sizeof (ap_prefix), sizeof (ap->s6_addr) - sizeof (ap_prefix));
}
