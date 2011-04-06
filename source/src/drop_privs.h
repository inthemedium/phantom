#ifndef __HAVE_DROP_PRIVS_H__
#define __HAVE_DROP_PRIVS_H__

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#undef _BSD_SOURCE
#else
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#endif

int drop_privileges(const char *user);
#endif
