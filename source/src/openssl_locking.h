#ifndef __HAVE_OPENSSL_LOCKING_HH
#define __HAVE_OPENSSL_LOCKING_HH

#include <pthread.h>
#include <openssl/crypto.h>
#include <stdlib.h>

int init_locks(void);
void kill_locks(void);

#endif
