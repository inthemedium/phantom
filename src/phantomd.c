#include "phantomd.h"

static int quit = 0;

static void
daemonize(void)
{
	pid_t pid, sid;
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}
	umask(0);
	sid = setsid();
	if (sid < 0) {
		perror("setsid");
		exit(EXIT_FAILURE);
	}
	if (chdir("/") < 0) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}
	assert(freopen("/dev/null", "r", stdin) != NULL);
	assert(freopen("/dev/null", "w", stdout) != NULL);
	assert(freopen("/dev/null", "w", stderr) != NULL);
}

static void
handler(int signum)
{
	if (signum == SIGTERM) {
		quit = 1;
	}
}

static void
setup_signal(void)
{
	struct sigaction action;
	sigset_t signal_mask;
	int ret;
	bzero(&action, sizeof (struct sigaction));
	ret = sigemptyset(&action.sa_mask);
	if (ret != 0) {
		perror("sigemptyset");
		exit(EXIT_FAILURE);
	}
	action.sa_handler = handler;
	ret = sigaction(SIGTERM, &action, NULL);
	if (ret != 0) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
	ret = sigemptyset(&signal_mask);
	if (ret != 0) {
		perror("sigemptyset");
		exit(EXIT_FAILURE);
	}
	ret = sigaddset(&signal_mask, SIGPIPE);
	if (ret != 0) {
		perror("sigaddset");
		exit(EXIT_FAILURE);
	}
	ret = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (ret != 0) {
		perror("sigprocmask");
		exit(EXIT_FAILURE);
	}
}

static int
address_ok(const uint8_t *addr)
{
	static const uint8_t prefix[] = AP_PREFIX;
	assert(sizeof (prefix) <= 16);
	return !memcmp(addr, prefix, sizeof (prefix));
}

struct request {
	int add_addr;
	int rem_addr;
	uint8_t addr[16];
	const char *dev_name;
	int s;
};

static void
read_request(int fd, struct request *r)
{
	uint8_t buf[17];
	struct sockaddr addr;
	socklen_t size;
	while (! quit) {
		size = sizeof (addr);
		if ((r->s = accept(fd, &addr, &size)) < 0) {
			continue;
		}
		if (read(r->s, buf, 17) != 17) {
			close(r->s);
			continue;
		}
		if (buf[0] != 'a' && buf[0] != 'd') {
			close(r->s);
			continue;
		}
		if (buf[0] == 'a') {
			r->add_addr = 1;
			r->rem_addr = 0;
		} else {
			r->add_addr = 0;
			r->rem_addr = 1;
		}
		if (address_ok(buf + 1)) {
			memcpy(r->addr, buf + 1, 16);
			return;
		}
		close(r->s);
	}
}

/* FIXME rtnetlink suuuuuuuuux - still get rid of system */

static int
serve_request(const struct request *r)
{
	char command[4096], buf[100];
	const char *retp;
	static const uint8_t prefix[] = AP_PREFIX;
	int ret, mask;
	struct in6_addr s;
	memcpy(&s.s6_addr, r->addr, 16);
	retp = inet_ntop(AF_INET6, &s, buf, 100);
	if (retp == NULL) {
		return -1;
	}
	mask = sizeof (prefix) * 8;
	if (r->rem_addr) {
		snprintf(command, 4096, "/bin/ip -6 addr del %s/%d dev %s", buf, mask, r->dev_name);
	} else {
		snprintf(command, 4096, "/bin/ip -6 addr add %s/%d dev %s", buf, mask, r->dev_name);
	}
	command[sizeof (command) - 1] = 0;
	ret = system(command);
	if (ret == -1) {
		return -1;
	}
	return (ret == 0)? 0 : -1;
}

static void
nak_request(struct request *r)
{
	const char nack = '1';
	assert(write(r->s, &nack, sizeof (nack)) == sizeof (nack));
}

static void
ack_request(struct request *r)
{
	const char ack = '0';
	assert(write(r->s, &ack, sizeof (ack)) == sizeof (ack));
}

int
main(int argc, char **argv)
{
	struct request r;
	struct sockaddr_un name;
	int ret, size, fd;
	r.dev_name = DEVICE_NAME;
	(void) argc;
	(void) argv;
	setup_signal();
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	name.sun_family = AF_FILE;
	assert(sizeof(name.sun_path) >= strlen(SOCKNAME) + 1);
	strncpy(name.sun_path, SOCKNAME, sizeof(name.sun_path));
	size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path) + 1);
	unlink(SOCKNAME);
	if (bind (fd, (struct sockaddr *) &name, size) < 0) {
		perror ("bind");
		exit (EXIT_FAILURE);
	}
	ret = chmod(SOCKNAME, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (ret != 0) {
		perror("chmod");
		exit (EXIT_FAILURE);
	}
	if (listen(fd, 5) != 0) {
		perror("listen");
		exit (EXIT_FAILURE);
	}
	daemonize();
	while (! quit) {
		read_request(fd, &r);
		ret = serve_request(&r);
		if (ret != 0) {
			nak_request(&r);
		} else {
			ack_request(&r);
		}
		close(r.s);
	}
	unlink(SOCKNAME);
	close(fd);
	exit(EXIT_SUCCESS);
}
