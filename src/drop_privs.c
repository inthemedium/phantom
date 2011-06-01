#include "drop_privs.h"
int
drop_privileges(const char *user)
{
	int ret;
	struct passwd *pw;
	uid_t newuid;
	gid_t newgid;
	pw = getpwnam(user);
	if (pw == NULL) {
		return -1;
	}
	newuid = pw->pw_uid;
	newgid = pw->pw_gid;
	ret = setgroups(1, &newgid);
	if (ret == -1) {
		return -1;
	}
	ret = setregid(newgid, newgid);
	if (ret == -1) {
		return -1;
	}
	ret = setreuid(newuid, newuid);
	if (ret == -1) {
		return -1;
	}
	if (getuid() == 0) {
		return -1;
	}
	if (geteuid() == 0) {
		return -1;
	}
	if (getgid() == 0) {
		return -1;
	}
	if (getegid() == 0) {
		return -1;
	}
	return 0;
}
