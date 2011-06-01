#include "measure.h"

static struct timespec start;
static struct timespec *begin = &start;


static void
delta_t(struct timespec *interval, struct timespec *now)
{
	interval->tv_nsec = now->tv_nsec - begin->tv_nsec;
	if (interval->tv_nsec < 0 ) {
		interval->tv_nsec += 1000000000;
		interval->tv_sec = now->tv_sec - begin->tv_sec - 1;
	} else {
		interval->tv_sec = now->tv_sec - begin->tv_sec;
	}
}

void
start_measure(void)
{
	assert(! clock_gettime(CLOCK_MONOTONIC, begin));
}

void
stop_measure(void)
{
	struct timespec now, interval;
	double zt = 0;
	assert(! clock_gettime(CLOCK_MONOTONIC, &now));
	delta_t(&interval, &now);
	zt = interval.tv_sec+interval.tv_nsec/1000000000.0;
	printf("%10.6f\n", zt);
}
