#include "diskcache.h"

static struct disk_record *
new_record(FILE *file, struct kad_metadata *metadata)
{
	struct disk_record *out;
	assert(file);
	out = malloc(sizeof (struct disk_record));
	if (out == NULL) {
		return NULL;
	}
	out->file = file;
	out->metadata = metadata;
	return out;
}

static void
free_record(struct disk_record *r)
{
	fclose(r->file);
	r->file = NULL;
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
	uint32_t have;
	struct disk_record *help1, *help2, *r;
	FILE *file;
	assert(d);
	assert(metadata);
	assert(data);
	assert(len);
	if (len > INT_MAX) {
		return -1;
	}

	pthread_mutex_lock(&d->lock);
	printf("storing key %s, v%d\n",
                   bin_to_hex(metadata->key, SHA_DIGEST_LENGTH),
                   metadata->version);
	LIST_for_all(&d->files, help1, help2) {
		if (! memcmp(help1->metadata->key, metadata->key, SHA_DIGEST_LENGTH)) {
          printf("replacing data! old %d, new %d\n",
                 help1->metadata->version, metadata->version);
			LIST_remove(help1);
			free_record(help1);
			break;
		}
	}

	file = tmpfile();
	if (file == NULL) {
		pthread_mutex_unlock(&d->lock);
		return -1;
	}

	r = new_record(file, metadata);
	printf("new data! version %d\n", metadata->version);
	if (r == NULL) {
		fclose(file);
		pthread_mutex_unlock(&d->lock);
		return -1;
	}

	have = 0;
	while (have < len) {
		ret = fwrite(data + have, len - have, 1, file);
		if (ret == 0) {
			free_record(r);
			pthread_mutex_unlock(&d->lock);
			return -1;
		}
		have += ret * len;
	}
	assert(have == len);
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
	size_t want, have;
	struct disk_record *help1, *help2;
	FILE *file = NULL;
	assert(d);
	assert(key);
	assert(outsize);

	pthread_mutex_lock(&d->lock);

	LIST_for_all(&d->files, help1, help2) {
		if (! memcmp(help1->metadata->key, key, SHA_DIGEST_LENGTH)) {
	printf("found key %s, v%d\n",
                   bin_to_hex(help1->metadata->key, SHA_DIGEST_LENGTH),
                   help1->metadata->version);
			file = help1->file;
			break;
		}
	}

	/* key is not among records */
	if (file == NULL) {
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}

	ret = fseek(file, 0L, SEEK_END);
	if (ret != 0) {
		perror("fseek");
	}
	want = ftell(file);
	assert(want);
	rewind(file);
	out = malloc(want);
	if (out == NULL) {
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}
	have = 0;
	while (have < want) {
		ret = fread(out + have, want - have, 1, file);
		if (ret == 0) {
			if (! feof(file)) {
				free(out);
				pthread_mutex_unlock(&d->lock);
				return NULL;
			}
		}
		have += want * ret;
	}
	assert(have == want);
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
			printf("deleting key %s, v%d\n",
                   bin_to_hex(help1->metadata->key, SHA_DIGEST_LENGTH),
                   help1->metadata->version);
			/* TODO: consider putting this in some kind of recently removed list */
			printf("deleting something\n");
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
