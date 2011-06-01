#include "logger.h"

static struct logger *logger;

int
start_logger(const char *logfile)
{
	assert(logfile);
	logger = malloc(sizeof (struct logger));
	if (logger == NULL) {
		return -1;
	}
	pthread_mutex_init(&(logger->lock), NULL);
	logger->fd = fopen(logfile, "a");
	if (logger->fd == NULL) {
		free(logger);
		logger = NULL;
		return -1;
	}
	return 0;
}

void
write_log(const char *msg)
{
	assert(msg);
	assert(logger);
	pthread_mutex_lock(&(logger->lock));
	fprintf(logger->fd, "%s\n", msg);
	pthread_mutex_unlock(&(logger->lock));
}

void stop_logger(void)
{
	assert(logger);
	pthread_mutex_destroy(&(logger->lock));
	fclose(logger->fd);
	free(logger);
}
