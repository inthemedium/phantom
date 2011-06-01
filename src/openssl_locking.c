#include "openssl_locking.h"

static pthread_mutex_t *locks;

static void
lock_callback(int mode, int type, const char *file, int line)
{
	(void) file;
	(void) line;
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(locks[type]));
	} else {
		pthread_mutex_unlock(&(locks[type]));
	}
}

static unsigned long
thread_id(void)
{
	return (unsigned long) pthread_self();
}

int
init_locks(void)
{
	int i;
	locks = malloc(CRYPTO_num_locks() * sizeof (pthread_mutex_t));
	if (locks == NULL) {
		return -1;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(locks[i]), NULL);
	}
	CRYPTO_set_id_callback(thread_id);
	CRYPTO_set_locking_callback(lock_callback);
	return 0;
}

void
kill_locks(void)
{
	int i;
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(locks[i]));
	}
	free(locks);
}
