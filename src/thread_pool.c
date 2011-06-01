#include "thread_pool.h"

static void
jump_off(struct thread_descriptor *desc)
{
	while (1) {
		sem_wait(desc->runn_sem);
		if (*desc->fini) {
			return;
		}
		desc->start_func(desc->arg);
		if (desc->arg) {
			desc->free_func(desc->arg);
		}
		pthread_mutex_lock(desc->lock);
		*desc->self = 0;
		pthread_mutex_unlock(desc->lock);
		sem_post(desc->sem);
	}
}

static void
take_down_threads(struct thread_pool *t)
{
	int i;
	assert(t);
	assert(! t->fini);
	t->fini = 1;
	for (i = 0; i < t->nthreads; i++) {
		sem_wait(&t->sem);
	}
	for (i = 0; i < t->nthreads; i++) {
		sem_post(&t->sems[i]);
	}
	for (i = 0; i < t->nthreads; i++) {
		assert(! pthread_join(t->descs[i].pid, NULL));
	}
}

struct thread_pool *
new_thread_pool(int nthreads)
{
	int ret, i;
	struct thread_pool *t;
	assert(nthreads > 0);
	t = malloc(sizeof (struct thread_pool));
	if (t == NULL) {
		return NULL;
	}
	t->running = calloc(nthreads, sizeof (int));
	if (t->running == NULL) {
		free(t);
		return NULL;
	}
	t->descs = calloc(nthreads, sizeof (struct thread_descriptor));
	if (t->descs == NULL) {
		free(t->running);
		free(t);
		return NULL;
	}
	t->sems = malloc(nthreads * sizeof (sem_t));
	if (t->sems == NULL) {
		free(t->descs);
		free(t->running);
		free(t);
		return NULL;
	}
	t->nthreads = nthreads;
	t->fini = 0;
	pthread_mutex_init(&t->lock, NULL);
	sem_init(&t->sem, 0, nthreads);
	for (i = 0; i < nthreads; i++) {
		sem_init(&t->sems[i], 0, 0);
		t->descs[i].sem = &t->sem;
		t->descs[i].runn_sem = &t->sems[i];
		t->descs[i].lock = &t->lock;
		t->descs[i].fini = &t->fini;
		t->descs[i].self = &t->running[i];
		ret = pthread_create(&t->descs[i].pid, NULL, (void *(*)(void *)) jump_off, (void *) &t->descs[i]);
		if (ret != 0) {
			t->nthreads = i - 1;
			take_down_threads(t);
			free(t->descs);
			free(t->running);
			free(t);
			return NULL;
		}
	}
	return t;
}

void free_thread_pool(struct thread_pool *t)
{
	int i;
	assert(t);
	take_down_threads(t);
	sem_destroy(&t->sem);
	for (i = 0; i < t->nthreads; i++) {
		sem_destroy(&t->sems[i]);
	}
	free(t->running);
	free(t->descs);
	free(t->sems);
	pthread_mutex_destroy(&t->lock);
	free(t);
}

int
thread_pool_dispatch(struct thread_pool *t, void *arg, void (*free_func)(void *), void (*start_func)(void *))
{
	int i, idx;
	assert(t);
	assert(start_func);
	if (arg) {
		assert(free_func);
	}
	assert(! t->fini);
	idx = -1;
	sem_wait(&t->sem);
	pthread_mutex_lock(&t->lock);
	for (i = 0; i < t->nthreads; i++) {
		if (! t->running[i]) {
			idx = i;
			t->running[i] = 1;
			break;
		}
	}
	pthread_mutex_unlock(&t->lock);
	assert(idx != -1);
	t->descs[idx].arg = arg;
	t->descs[idx].free_func = free_func;
	t->descs[idx].start_func = start_func;
	sem_post(&t->sems[i]);
	return 0;
}
