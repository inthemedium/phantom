#include "tun.h"

static struct tun_dev *
new_tun(const struct config *config)
{
	struct tun_dev *t;
	struct ifreq ifr;
	int fd, ret;
	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		return NULL;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, "phantom", IFNAMSIZ);
	ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
	if (ret < 0) {
		close(fd);
		return NULL;
	}
	t = malloc(sizeof (struct tun_dev));
	if (t == NULL) {
		close(fd);
		return NULL;
	}
	t->fd = fd;
	t->quit = 0;
	t->has_awaiter = 0;
	t->config = config;
	strncpy(t->name, ifr.ifr_name, IFNAMSIZ);
	LIST_init(&t->map);
	pthread_mutex_init(&t->map_mutex, NULL);
	pthread_mutex_init(&t->write_lock, NULL);
	return t;
}

static void
free_tun(struct tun_dev *t)
{
	struct ap_to_tun *help;
	close(t->fd);
	LIST_clear(&t->map, help);
	pthread_mutex_destroy(&t->map_mutex);
	free(t);
}

static void __attribute__((unused))
package_info(const char *prefix, const uint8_t *buf, uint32_t size)
{
	struct in6_addr s, d;
	char buf1[100], buf2[100];
	memcpy(s.s6_addr, buf + 8, 16);
	memcpy(d.s6_addr, buf + 8 + 16, 16);
	assert(inet_ntop(AF_INET6, &s, buf1, 100) != NULL);
	assert(inet_ntop(AF_INET6, &d, buf2, 100) != NULL);
	printf("%s: src ip: %s dest ip: %s (%d bytes)\n", prefix, buf1, buf2, size);
}

static int
tun_dev_send_package(struct tun_dev *t, const uint8_t *buf, uint32_t size)
{
	int ret;
	uint32_t written;
	written = 0;
	assert(size && size <= MAX_MTU_SIZE);
	/*package_info("device send ", buf, size);*/
	pthread_mutex_lock(&t->write_lock);
	while (written < size) {
		ret = write(t->fd, buf + written, size - written);
		if (ret < 0) {
			pthread_mutex_unlock(&t->write_lock);
			return -1;
		}
		written += ret;
	}
	pthread_mutex_unlock(&t->write_lock);
	return 0;
}

static int
tun_dev_recv_package(struct tun_dev *t, uint8_t *buf, uint32_t *size)
{
	int ret;
	assert(*size && *size >= MAX_MTU_SIZE);
	ret = read(t->fd, buf, *size);
	if (ret < 0) {
		return -1;
	}
	*size = ret;
	assert(*size >= 40);
	/*package_info("device receive ", buf, *size);*/
	return 0;
}

static int
tunnel_send_package(struct tunnel *t, const uint8_t *buf, uint32_t size)
{
	int ret;
	uint8_t sbuf[4];
	uint32_t written;
	assert(size && size <= MAX_MTU_SIZE);
	serialize_32_t(size, sbuf);
	ret = tunnel_write(t, sbuf, 4);
	/*package_info("tunnel_send ", buf, size);*/
	if (ret != 4) {
		return -1;
	}
	written = 0;
	while (written < size) {
		ret = tunnel_write(t, buf + written, size - written);
		if (ret < 0) {
			return -1;
		}
		written += ret;
	}
	return 0;
}

static int
tunnel_recv_package(struct tunnel *t, uint8_t *buf, uint32_t *size)
{
	uint32_t have, want;
	int ret;
	uint8_t sbuf[4];
	have = 0;
	assert(*size && *size <= MAX_MTU_SIZE);
	while (have < 4) {
		ret = tunnel_read(t, sbuf + have, 4 - have);
		if (ret < 0) {
			return -1;
		}
		have += ret;
	}
	want = deserialize_32_t(sbuf);
	if (*size < want) {
		fprintf(stderr, "tunnel receive buffer too small, package says its %d bytes have buffer of size %d bytes\n", want, *size);
		return -1;
	}
	have = 0;
	while (have < want) {
		ret = tunnel_read(t, buf + have, want - have);
		if (ret < 0) {
			return -1;
		}
		have += ret;
	}
	/*package_info("tunnel_receive ", buf, want);*/
	*size = want;
	return 0;
}

struct tid_list {
	struct tid_list *prev;
	struct tid_list *next;
	pthread_t tid;
};

struct tunnel_reader_data {
	int *quit;
	struct tun_dev *td;
	struct tunnel *t;
};

static int
tunnel_reader(struct tunnel_reader_data *a)
{
	uint8_t buf[MAX_MTU_SIZE];
	int ret, inserted, retval;
	uint32_t size;
	struct pollfd fds[1];
	inserted = (a->t->is_entry_tunnel)? 0 : 1;
	retval = 0;
	while (! *a->quit) {
		fds[0].fd = a->t->conn->socket;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		ret = poll(fds, 1, 1000);
		if (ret < 0) {
			retval = -1;;
			goto out;
		}
		size = sizeof (buf);
		ret = tunnel_recv_package(a->t, buf, &size);
		if (ret != 0) {
			retval = -1;
			goto out;
		}
		if (! inserted) {
			struct ap_to_tun *new;
			new = malloc (sizeof (struct ap_to_tun));
			if (new == NULL) {
				retval = -1;
				goto out;
			}
			memcpy(new->ap.s6_addr, buf + 8, 16);
			new->tun = a->t;
			pthread_mutex_lock(&a->td->map_mutex);
			LIST_insert(&a->td->map, new);
			pthread_mutex_unlock(&a->td->map_mutex);
			inserted = 1;
		}
		ret = tun_dev_send_package(a->td, buf, size);
		if (ret != 0) {
			continue;
		}
	}
out:
	if (a->t->is_entry_tunnel && inserted) {
		struct ap_to_tun *help1, *help2;
		pthread_mutex_lock(&a->td->map_mutex);
		LIST_for_all(&a->td->map, help1, help2) {
			if (help1->tun == a->t) {
				LIST_remove(help1);
				break;
			}
		}
		pthread_mutex_unlock(&a->td->map_mutex);
		free_tunnel(help1->tun);
		free(help1);
	}
	free(a);
	return retval;
}

struct reader_data {
	int *quit;
	struct tun_dev *t;
	const struct path *path;
};

static int
reader(struct reader_data *a)
{
	int ret;
	struct tunnel *out_tun;
	uint32_t size;
	uint8_t buf[MAX_MTU_SIZE];
	struct ap_to_tun *help1, *help2;
	struct tid_list childs, *chelp1, *chelp2;
	help1 = NULL; /*gcc complaints about uninitizlized value if not done
	like this */
	LIST_init(&childs);
	while (! *a->quit) {
		size = sizeof (buf);
		ret = tun_dev_recv_package(a->t, buf, &size);
		if (ret != 0) {
			continue;
		}
		out_tun = NULL;
		pthread_mutex_lock(&a->t->map_mutex);
		LIST_for_all(&a->t->map, help1, help2) {
			if (! memcmp(buf + 24, help1->ap.s6_addr, 16)) {
				out_tun = help1->tun;
				break;
			}
		}
		pthread_mutex_unlock(&a->t->map_mutex);
		if (! out_tun && a->path->is_entrypath) {
			continue;
		}
		if (! out_tun) {
			struct ap_to_tun *new;
			struct in6_addr ap;
			struct tid_list *newtid;
			struct tunnel_reader_data *trd;
			memcpy(&ap.s6_addr, buf + 24, 16);
			out_tun = create_tunnel(&ap, a->path);
			if (out_tun == NULL) {
				printf("could not create tunnel on demand\n");
				continue;
			}
			new = malloc(sizeof (struct ap_to_tun));
			if (new == NULL) {
				free_tunnel(out_tun);
				continue;
			}
			memcpy(new->ap.s6_addr, buf + 24, 16);
			new->tun = out_tun;
			pthread_mutex_lock(&a->t->map_mutex);
			LIST_insert(&a->t->map, new);
			pthread_mutex_unlock(&a->t->map_mutex);
			newtid = malloc (sizeof (struct tid_list));
			if (newtid == NULL) {
				free(new);
				free_tunnel(out_tun);
				continue;
			}
			trd = malloc(sizeof (struct tunnel_reader_data));
			if (trd == NULL) {
				free(new);
				free(newtid);
				free_tunnel(out_tun);
				continue;
			}
			trd->quit = a->quit;
			trd->td = a->t;
			trd->t = out_tun;
			ret = pthread_create(&newtid->tid, NULL, (void *(*)(void *)) tunnel_reader, trd);
			if (ret != 0) {
				printf("could not create worker thread\n");
				free(new);
				free(trd);
				free(newtid);
				free_tunnel(out_tun);
				continue;
			}
			LIST_insert(&childs, newtid);
		}
		assert(out_tun);
		ret = tunnel_send_package(out_tun, buf, size);
		if (ret != 0){
			printf("error sending package\n");
		}
	}
	LIST_for_all(&childs, chelp1, chelp2) {
		pthread_join(chelp1->tid, NULL);
		free(help1);
	}
	free(a);
	return 0;
}

struct awaiter_data {
	int *quit;
	const struct config *config;
	const struct path *path;
	struct tun_dev *t;
};

static int
awaiter(struct awaiter_data *a)
{
	int ret;
	struct tunnel *new;
	struct tid_list childs, *help1, *help2, *tid;
	struct in6_addr dummy;
	struct tunnel_reader_data *trd;
	LIST_init(&childs);
	while (! *a->quit) {
		new = await_entry_tunnel(&a->path->ap, &dummy, a->path, a->config);
		if (new == NULL) {
			printf("incoming tunnel creation failed\n");
			continue;
		}
		trd = malloc(sizeof (struct tunnel_reader_data));
		if (trd == NULL) {
			free_tunnel(new);
			continue;
		}
		trd->t = new;
		trd->td = a->t;
		trd->quit = a->quit;
		tid = malloc (sizeof (struct tid_list));
		if (tid == NULL) {
			free(trd);
			free_tunnel(new);
			continue;
		}
		ret = pthread_create(&tid->tid, NULL, (void *(*)(void *)) tunnel_reader, trd);
		if (ret != 0) {
			free(trd);
			free_tunnel(new);
			continue;
		}
		LIST_insert(&childs, tid);
	}
	LIST_for_all(&childs, help1, help2) {
		pthread_join(help1->tid, NULL);
		free(help1);
	}
	free(a);
	return 0;
}

struct tun_dev *
start_forwarding(struct path *path, const struct config *config)
{
	int ret;
	struct tun_dev *t;
	struct reader_data *rd;
	t = new_tun(config);
	if (t == NULL) {
		return NULL;
	}
	ret = set_addr(&path->ap);
	if (ret != 0) {
		free_tun(t);
		return NULL;
	}
	rd = malloc (sizeof (struct reader_data));
	if (rd == NULL) {
		free_tun(t);
		return NULL;
	}
	rd->quit = &t->quit;
	rd->t = t;
	rd->path = path;
	ret = pthread_create(&t->reader, NULL, (void *(*)(void *)) reader, rd);
	if (ret != 0) {
		free(rd);
		free_tun(t);
		return NULL;
	}
	if (path->is_entrypath) {
		struct awaiter_data *ad = malloc(sizeof (struct awaiter_data));
		if (ad == NULL) {
			t->quit = 1;
			pthread_join(t->reader, NULL);
			free_tun(t);
			return NULL;
		}
		ad->quit = &t->quit;
		ad->path = path;
		ad->config = config;
		ad->t = t;
		ret = pthread_create(&t->awaiter, NULL, (void *(*)(void *)) awaiter, ad);
		if (ret != 0) {
			t->quit = 1;
			pthread_join(t->reader, NULL);
			free(ad);
			free_tun(t);
			return NULL;
		}
		t->has_awaiter = 1;
	}
	return t;
}

void
stop_forwarding(struct tun_dev *t)
{
	t->quit = 1;
	pthread_join(t->reader, NULL);
	if (t->has_awaiter) {
		pthread_join(t->awaiter, NULL);
	}
	free_tun(t);
}
