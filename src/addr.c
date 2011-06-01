#include "addr.h"

static int
send_msg(struct in6_addr *addr, char prefix)
{
	uint8_t msg[17];
	struct sockaddr_un name;
	int s, ret;
	size_t size;
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		return -1;
	}
	name.sun_family = AF_FILE;
	assert(sizeof(name.sun_path) >= strlen(SOCKNAME) + 1);
	strncpy(name.sun_path, SOCKNAME, sizeof(name.sun_path));
	size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path) + 1);
	ret = connect(s, (struct sockaddr *) &name, size);
	if (ret < 0) {
		close(s);
		return -1;
	}
	msg[0] = prefix;
	memcpy(msg + 1, addr->s6_addr, 16);
	ret = write(s, msg, 17);
	if (ret != 17) {
		close(s);
		return -1;
	}
	ret = read(s, msg, 1);
	close(s);
	if (ret != 1) {
		return -1;
	}
	if (msg[0] == '0') {
		return 0;
	}
	return -1;
}

int
set_addr(struct in6_addr *addr)
{
	int ret;
	ret = send_msg(addr, 'a');
	if (ret != 0) {
		printf("Talking to phantomd failed in set_addr\n");
	}
	return ret;
}

int
del_addr(struct in6_addr *addr)
{
	int ret;
	ret = send_msg(addr, 'd');
	if (ret != 0) {
		printf("Talking to phantomd failed in del_addr\n");
	}
	return ret;
}
