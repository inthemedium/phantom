#include "diskcache.h"

static char *
filename(const struct disk_cache *d, const uint8_t *key)
{
	int ret;
	char *name, *buf;
	name = bin_to_hex(key, SHA_DIGEST_LENGTH);
	if (name == NULL) {
		return NULL;
	}
	buf = malloc(d->len + 2 * SHA_DIGEST_LENGTH + 10); /* enough */
	if (buf == NULL) {
		free(name);
		return NULL;
	}
	ret = sprintf(buf, "%s/%s", d->dirname, name); /*XXX snprintf not in posix */
	free(name);
	if (ret == -1) {
		free(buf);
		return NULL;
	}
	return buf;
}

static struct disk_record *
new_record(char *file)
{
	struct disk_record *out;
	assert(file);
	out = calloc(sizeof (struct disk_record), 1);
	if (out == NULL) {
		return NULL;
	}
	out->name = file;
	out->len = strlen(file);
	return out;
}

static void
free_record(struct disk_record *r)
{
	unlink(r->name);
	free(r->name);
	free(r);
}

struct disk_cache *
new_disk_cache(const char *dirname)
{
	struct disk_cache *d;
	assert(dirname);
	d = malloc(sizeof(struct disk_cache));
	if (d == NULL) {
		return NULL;
	}
	d->dirname = strdup(dirname);
	if (d->dirname == NULL) {
		free(d);
		return NULL;
	}
	d->len = strlen(dirname);
	pthread_mutex_init(&d->lock, NULL);
	LIST_init(&d->files);
	return d;
}

void
free_disk_cache(struct disk_cache *d)
{
	struct disk_record *help1, *help2;
	assert(d);
	pthread_mutex_destroy(&d->lock);
	LIST_for_all(&d->files, help1, help2) {
		LIST_remove(help1);
		free_record(help1);
	}
	free(d->dirname);
	free(d);
}

int
disk_cache_store(struct disk_cache *d, const uint8_t *key, const uint8_t *data, uint32_t len)
{
	int ret, fd;
	char *name;
	uint32_t have;
	struct disk_record *r, *help1, *help2;
	assert(d);
	assert(key);
	assert(data);
	assert(len);
	if (len > INT_MAX) {
		return -1;
	}
	name = filename(d, key);
	if (name == NULL) {
		return -1;
	}
	pthread_mutex_lock(&d->lock);
	if (access(name, R_OK | W_OK) == 0) {
		int slen = strlen(name);
		LIST_for_all(&d->files, help1, help2) {
			if (! memcmp(help1->name, name, (help1->len > slen)? slen : help1->len)) {
				assert(! clock_gettime(CLOCK_REALTIME, &help1->time));
				pthread_mutex_unlock(&d->lock);
				free(name);
				return 0;
			}
		}
		assert(0);
	}
	r = new_record(name);
	if (r == NULL) {
		free(name);
		return -1;
	}
	fd = creat(name, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		free_record(r);
		pthread_mutex_unlock(&d->lock);
		return -1;
	}
	have = 0;
	while (have < len) {
		ret = write(fd, data + have, len - have);
		if (ret == -1) {
			free_record(r);
			pthread_mutex_unlock(&d->lock);
			close(fd);
			return -1;
		}
		have += ret;
	}
	assert(have == len);
	close(fd);
	assert(! clock_gettime(CLOCK_REALTIME, &r->time));
	LIST_insert(&d->files, r);
	pthread_mutex_unlock(&d->lock);
	return 0;
}

uint8_t *
disk_cache_find(struct disk_cache *d, const uint8_t *key, size_t *outsize)
{
	char *name;
	uint8_t *out;
	int fd, ret;
	uint32_t want, have;
	struct stat s;
	assert(d);
	assert(key);
	assert(outsize);
	name = filename(d, key);
	if (name == NULL) {
		return NULL;
	}
	bzero(&s, sizeof (struct stat));
	pthread_mutex_lock(&d->lock);
	ret = stat(name, &s);
	if (ret == -1) {
		pthread_mutex_unlock(&d->lock);
		free(name);
		return NULL;
	}
	fd = open(name, O_RDONLY);
	free(name);
	if (fd == -1) {
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}
	want = s.st_size;
	out = malloc(want);
	if (out == NULL) {
		close(fd);
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}
	have = 0;
	while (have < want) {
		ret = read(fd, out + have, want - have);
		if (ret == -1) {
			close(fd);
			free(out);
			pthread_mutex_unlock(&d->lock);
			return NULL;
		}
		have += ret;
	}
	assert(have == want);
	close(fd);
	pthread_mutex_unlock(&d->lock);
	*outsize = have;
	return out;
}

void
disk_cache_house_keeping(struct disk_cache *d)
{
	assert(d);
}
