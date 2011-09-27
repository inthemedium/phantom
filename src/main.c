#include <stddef.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <paths.h>
#include "config.h"
#include "helper.h"
#include "server.h"
#include "logger.h"
#include "openssl_locking.h"
#include "path.h"
#include "kademlia.h"
#include "tun.h"
#include "drop_privs.h"
#include "addr.h"

extern char **environ;

static int
block_sigpipe(void)
{
	int ret;
	sigset_t signal_mask;
	ret = sigemptyset(&signal_mask);
	if (ret != 0) {
		return -1;
	}
	ret = sigaddset(&signal_mask, SIGPIPE);
	if (ret != 0) {
		return -1;
	}
	ret = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

static char **
sanitize_environment(void)
{
	int i;
	char **new_env, *new_entry, *entry;
	char **old_env;
	int nentries, nnew_entries, len, size;
	static const char *base[] = {
		"IFS= \t\n",
		"PATH=" _PATH_STDPATH,
		NULL
	};
	static const char *preserve[] = {
		"TZ",
		NULL
	};
	size = 0;
	nentries = 1;
	for (i = 0; base[i] != NULL; i++) {
		size += strlen(base[i]) + 1;
		nentries++;
	}
	for (i = 0; preserve[i] != NULL; i++) {
		entry = getenv(preserve[i]);
		if (entry == NULL) {
			continue;
		}
		size += strlen(preserve[i]) + strlen(entry) + 2;
		nentries++;
	}
	size += (nentries * sizeof(char *));
	new_env = malloc(size);
	if (new_env == NULL) {
		printf("failed to sanitize environment\n");
		abort();
	}
	new_env[nentries - 1] = NULL;
	new_entry = (char *) new_env + (nentries * sizeof(char *));
	nnew_entries = 0;
	for (i = 0; base[i] != NULL; i++) {
		new_env[nnew_entries++] = new_entry;
		len = strlen(base[i]);
		memcpy(new_entry, base[i], len + 1);
		new_entry += len + 1;
	}
	for (i = 0; preserve[i] != NULL; i++) {
		entry = getenv(preserve[i]);
		if (entry == NULL) {
			continue;
		}
		new_env[nnew_entries++] = new_entry;
		len = strlen(preserve[i]);
		memcpy(new_entry, preserve[i], len);
		*(new_entry + len + 1) = '=';
		memcpy(new_entry + len + 2, entry, strlen(entry) + 1);
		new_entry += len + strlen(entry) + 2;
	}
	old_env = environ;
	environ = new_env;
	umask(022);
	return old_env;
}

static void
reset_environment(char **oldenv)
{
	char **p = environ;
	environ = oldenv;
	free(p);
}

static void
init_randgen(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	assert (RAND_status() == 1); /* NFC */
	OpenSSL_add_all_algorithms();
}

struct app {
	struct path *path;
	struct tun_dev *tun;
};

int
main(int argc, char **argv)
{
	int ret, quit, exit_path;
	struct config config;
	int c;
	char confname[HOST_NAME_MAX + 100], buf[100];
	struct app a;
	char **oldenv;
	(void) argv;
	(void) argc;
	quit = 0;
	ret = block_sigpipe();
	if (ret != 0) {
		printf("failed to block sigpipe\n");
		exit(EXIT_FAILURE);
	}

	confname[0] = 0;
	while ((c = getopt (argc, argv, "h:")) != -1) {
		switch (c) {
			case 'h':
				sprintf(confname, "logs/%s.log", optarg); /*XXX snprintf not in posix*/
				sprintf(confname, "test/%s.conf", optarg); /*XXX snprintf not in posix*/
				break;
			case '?':
				if (optopt == 'h') {
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				} else if (isprint(optopt)) {
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				} else {
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				}
				return 1;
			default:
				abort();
		}
	}
	if (confname[0] == 0) {
		struct utsname u;
		oldenv = sanitize_environment();
		bzero(&u, sizeof (struct utsname));
		ret = uname(&u);
		if (ret != 0) {
			printf("could not get hostname\n");
			exit(EXIT_FAILURE);
		}
		sprintf(confname, "logs/%s.log", u.nodename); /*XXX snprintf not in posix*/
		sprintf(confname, "test/%s.conf", u.nodename); /*XXX snprintf not in posix*/
	}
	fprintf(stdout, "Loading configuration file %s\n", confname);
	read_config(confname, &config);
	init_randgen();
	init_locks();
	ret = start_server(&config);
	if (ret) {
		printf("Server creation failed\n");
		exit(EXIT_FAILURE);
	}
	ret = start_kad(&config);
	if (ret != 0) {
		printf("failed to start kad\n");
		exit(EXIT_FAILURE);
	}
	bzero(&a, sizeof (struct app));
	exit_path = rand_range(0, 2);
	while (! a.path) {
		printf("starting to construct %s-path\n", (exit_path)? "exit" : "entry");
		if (exit_path) {
			a.path = construct_exit_path(&config);
		} else {
			a.path = construct_entry_path(&config);
		}
	}
	printf("path built successfully, have ap %s\n", inet_ntop(AF_INET6, &a.path->ap, buf, 100));
	a.tun = start_forwarding(a.path, &config);
	if (a.tun == NULL) {
		printf("starting the forwarder failed\n");
		exit(EXIT_FAILURE);
	}
	while (! quit) {
		poll(NULL, 0, 1000);
	}
	stop_forwarding(a.tun);
	free_path(a.path);
	stop_kad();
	stop_server();
	kill_locks();
	free_config(&config);
	EVP_cleanup();
	reset_environment(oldenv);
	exit(EXIT_SUCCESS);
}
