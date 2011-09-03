#include "diskcache.h"

static struct disk_record *
new_record(struct kad_metadata *metadata)
{
	struct disk_record *out;
	FILE * file;

	out = malloc(sizeof (struct disk_record));
	if (out == NULL) {
		return NULL;
	}
	file = tmpfile();
	if (file == NULL) {
		free(out);
		return NULL;
	}
	out->file = fileno(file);
	out->metadata = metadata;
	return out;
}

static void
free_record(struct disk_record *r)
{
	close(r->file);
	free(r->metadata);
	r->metadata = NULL;
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
disk_cache_store(struct disk_cache *d, struct kad_metadata *metadata, const uint8_t *data, uint32_t len)
{
	int ret;
	struct disk_record *help1, *help2, *r;

	assert(d);
	assert(metadata);
	assert(data);
	assert(len);
	if (len > INT_MAX) {
		return -1;
	}

	pthread_mutex_lock(&d->lock);
	LIST_for_all(&d->files, help1, help2) {
		if (! memcmp(help1->metadata->key, metadata->key, SHA_DIGEST_LENGTH)) {
			LIST_remove(help1);
			free_record(help1);
			break;
		}
	}

	r = new_record(metadata);
	if (r == NULL) {
		pthread_mutex_unlock(&d->lock);
		return -1;
	}

	r->file_len = 0;
	while (r->file_len < len) {
		ret = write(r->file, data + r->file_len, len - r->file_len);
		if (ret == -1) {
			free_record(r);
			pthread_mutex_unlock(&d->lock);
			return -1;
		}
		r->file_len += ret;
	}
	assert(r->file_len == len);
	assert(! clock_gettime(CLOCK_REALTIME, &r->metadata->exp_time));
	LIST_insert(&d->files, r);

	pthread_mutex_unlock(&d->lock);
	return 0;
}

uint8_t *
disk_cache_find(struct disk_cache *d, const uint8_t *key, size_t *outsize)
{
	uint8_t *out;
	int ret;
	size_t have;
	struct disk_record *help1, *help2, *found = NULL;

	assert(d);
	assert(key);
	assert(outsize);

	pthread_mutex_lock(&d->lock);

	LIST_for_all(&d->files, help1, help2) {
		if (! memcmp(help1->metadata->key, key, SHA_DIGEST_LENGTH)) {
			found = help1;
			break;
		}
	}

	/* key is not among records */
	if (! found) {
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}
	assert(found->file_len);
	lseek(found->file, 0, SEEK_SET);
	out = malloc(found->file_len);
	if (out == NULL) {
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}
	have = 0;
	while (have < found->file_len) {
		ret = read(found->file, out + have, found->file_len - have);
		if (ret == -1) {
			free(out);
			pthread_mutex_unlock(&d->lock);
			return NULL;
		}
		have += ret;
	}
	assert(have == found->file_len);
	*outsize = have;
	pthread_mutex_unlock(&d->lock);
	return out;
}

void
disk_cache_house_keeping(struct disk_cache *d)
{
	struct disk_record *help1, *help2;
	struct timespec t;
	assert(d);

	pthread_mutex_lock(&d->lock);
	assert(! clock_gettime(CLOCK_REALTIME, &t));
	LIST_for_all(&d->files, help1, help2) {
		if (t.tv_sec - help1->metadata->exp_time.tv_sec > 0) {
			/* TODO: consider putting this in some kind of recently removed list */
			LIST_remove(help1);
			free_record(help1);
		}
	}
	pthread_mutex_unlock(&d->lock);
}

int
in_disk_cache(struct disk_cache *d, const struct kad_metadata *metadata) {
	struct disk_record *help1, *help2;
	assert(d);

	pthread_mutex_lock(&d->lock);
	LIST_for_all(&d->files, help1, help2) {
		if (! memcmp(help1->metadata->key, metadata->key, SHA_DIGEST_LENGTH)) {
			/* key needs to be updated */
			if (metadata->version > help1->metadata->version){
				break;
			}

			/* already have this version of the key */
			pthread_mutex_unlock(&d->lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&d->lock);
	return -1;
}
