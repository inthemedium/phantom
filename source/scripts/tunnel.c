/*modeled after tunctl by Jeff Dike */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#ifndef TUNSETGROUP
#define TUNSETGROUP   _IOW('T', 206, int)
#endif

static void
usage(char *name)
{
	fprintf(stderr,
		"Create: %s [-b] [-u owner] [-g group] [-t device-name]\n",
		name);
	fprintf(stderr, "Delete: %s -d device-name\n", name);
}

int
main(int argc, char **argv)
{
	struct ifreq ifr;
	struct passwd *pw;
	struct group *gr;
	uid_t owner = -1;
	gid_t group = -1;
	int tun_fd, opt, delete = 0;
	const char *tun = "", *file = "/dev/net/tun";
	char *name = argv[0], *end;

	while ((opt = getopt(argc, argv, "bd:f:t:u:g:")) > 0) {
		switch (opt) {
			case 'd':
				delete = 1;
				tun = optarg;
				break;
			case 'u':
				pw = getpwnam(optarg);
				if (pw != NULL) {
					owner = pw->pw_uid;
					break;
				}
				owner = strtol(optarg, &end, 0);
				if (*end != '\0') {
					fprintf(stderr,
						"'%s' is neither a username nor a numeric uid.\n",
						optarg);
					usage(name);
					exit(EXIT_FAILURE);
				}
				break;
			case 'g':
				gr = getgrnam(optarg);
				if (gr != NULL) {
					group = gr->gr_gid;
					break;
				}
				group = strtol(optarg, &end, 0);
				if (*end != '\0') {
					fprintf(stderr,
						"'%s' is neither a groupname nor a numeric group.\n",
						optarg);
					usage(name);
					exit(EXIT_FAILURE);
				}
				break;

			case 't':
				tun = optarg;
				break;
			case 'h':
			default:
				usage(name);
				exit(EXIT_FAILURE);
		}
	}
	argv += optind;
	argc -= optind;
	if (argc > 0) {
		usage(name);
		exit(EXIT_FAILURE);
	}
	if ((tun_fd = open(file, O_RDWR)) < 0) {
		fprintf(stderr, "Failed to open '%s' : ", file);
		perror("");
		exit(1);
	}
	memset(&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_TUN | TUN_NO_PI;
	strncpy(ifr.ifr_name, tun, sizeof (ifr.ifr_name) - 1);
	if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		perror("TUNSETIFF");
		exit(1);
	}
	if (delete) {
		if (ioctl(tun_fd, TUNSETPERSIST, 0) < 0) {
			perror("disabling TUNSETPERSIST");
			exit(EXIT_FAILURE);
		}
		printf("Set '%s' nonpersistent\n", ifr.ifr_name);
	} else {
		/* emulate behaviour prior to TUNSETGROUP */
		if (owner == (uid_t) -1 && group == (gid_t) -1) {
			owner = geteuid();
		}
		if (owner != (uid_t) -1) {
			if (ioctl(tun_fd, TUNSETOWNER, owner) < 0) {
				perror("TUNSETOWNER");
				exit(EXIT_FAILURE);
			}
		}
		if (group != (gid_t) -1) {
			if (ioctl(tun_fd, TUNSETGROUP, group) < 0) {
				perror("TUNSETGROUP");
				exit(EXIT_FAILURE);
			}
		}
		if (ioctl(tun_fd, TUNSETPERSIST, 1) < 0) {
			perror("enabling TUNSETPERSIST");
			exit(EXIT_FAILURE);
		}
		printf("Set '%s' persistent and owned by", ifr.ifr_name);
		if (owner != (uid_t) -1)
			printf(" uid %d", owner);
		if (group != (gid_t) -1)
			printf(" gid %d", group);
		printf("\n");
	}
	exit(EXIT_SUCCESS);
}
