#ifndef __HAVE_THREAD_POOL_H__
#define __HAVE_THREAD_POOL_H__
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

struct thread_descriptor {
	pthread_t pid;
	void *arg;
	void (*free_func)(void *);
	void (*start_func)(void *);
	sem_t *sem;
	sem_t *runn_sem;
	int *self;
	int *fini;
	pthread_mutex_t *lock;
};

struct thread_pool {
	int nthreads;
	int fini;
	sem_t *sems;
	sem_t sem;
	int *running;
	struct thread_descriptor *descs;
	pthread_mutex_t lock;
};

struct thread_pool *new_thread_pool(int nthreads);
int thread_pool_dispatch(struct thread_pool *t, void *arg, void (*free_func)(void *), void (*start_func)(void *));
void free_thread_pool(struct thread_pool *t);

#endif
