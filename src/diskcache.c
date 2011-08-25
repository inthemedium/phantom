#include "diskcache.h"

static FILE *
new_file(const struct disk_cache *d)
{
	int ret, fd;
	char *buf;
	FILE *file;

	/* if (!secure_dir(d->dirname)) { */
	/* 	printf("insecure directory choice!\n"); */
	/* 	return NULL; */
	/* } */

	buf = malloc(d->len + 1 + TMP_X_NUM + 1); /* enough */
	if (buf == NULL) {
		return NULL;
	}
	ret = sprintf(buf, "%s/%s", d->dirname, TMP_X); /*XXX snprintf not in posix */
	if (ret == -1) {
		free(buf);
		return NULL;
	}
	fd = mkstemp(buf);
	if (fd == -1) {
		free(buf);
		return NULL;
	}

	/*
	* Unlink immediately to hide the file name.
	* The race condition here is inconsequential if the file
	* is created with exclusive permissions (glibc >= 2.0.7)
	*/

	if (unlink(buf) == -1) {
		free(buf);
		return NULL;
	}

	free(buf);

	file = fdopen(fd, "w+");
	if (file == NULL) {
		close(fd);
		return NULL;
	}

	return file;
}

static struct disk_record *
new_record(FILE *file, const uint8_t *key)
{
	struct disk_record *out;
	assert(file);
	out = calloc(sizeof (struct disk_record), 1);
	if (out == NULL) {
		return NULL;
	}
	out->file = file;
	memcpy(out->key, key, SHA_DIGEST_LENGTH);
	return out;
}

static void
free_record(struct disk_record *r)
{
	fclose(r->file);
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
	int ret;
	FILE *file;
	uint32_t have;
	struct disk_record *r;
	assert(d);
	assert(key);
	assert(data);
	assert(len);
	if (len > INT_MAX) {
		return -1;
	}
	file = new_file(d);
	if (file == NULL) {
		return -1;
	}
	pthread_mutex_lock(&d->lock);
	r = new_record(file, key);
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
	assert(! clock_gettime(CLOCK_REALTIME, &r->time));
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
		if (!memcmp(help1->key, key, SHA_DIGEST_LENGTH)) {
			file = help1->file;
			break;
		}
	}

	/* key is not among records */
	if (file == NULL) {
		pthread_mutex_unlock(&d->lock);
		return NULL;
	}

    fseek(file, 0L, SEEK_END);
	want = ftell(file);
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
	pthread_mutex_unlock(&d->lock);
	*outsize = have;
	return out;
}

void
disk_cache_house_keeping(struct disk_cache *d)
{
	assert(d);
}
