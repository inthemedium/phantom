#ifndef __HAVE_LOGGER_H__
#define __HAVE_LOGGER_H__

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

struct logger {
	FILE *fd;
	pthread_mutex_t lock;
};

int start_logger(const char *logfile);
void stop_logger(void);
void write_log(const char *msg);


#define LOGERRCHK(cond)			{\
					char buf[BUFSIZ]; \
					char error[BUFSIZ]; \
                                	if (cond) { \
						if (errno) { \
							strerror_r(errno, error, BUFSIZ); \
						}  else { \
							error[0] = '\0'; \
						}\
                                	        snprintf(buf, sizeof(buf), \
                                	                "\"%s\" in file %s: line %d: (function %s)", \
                                	                 error, __FILE__, (int) __LINE__, __FUNCTION__); \
                                	        write_log(buf); \
                                	} \
                                	}
#endif
