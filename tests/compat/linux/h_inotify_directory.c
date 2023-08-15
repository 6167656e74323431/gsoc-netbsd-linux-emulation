#include "h_linux.h"

#include <sys/null.h>

#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_inotify.h>

#define	INOTIFY_ALL_DIRECTORY	(LINUX_IN_ATTRIB|LINUX_IN_CREATE \
				|LINUX_IN_MOVE_SELF|LINUX_IN_MOVED_FROM \
				|LINUX_IN_MOVED_TO|LINUX_IN_DELETE \
				|LINUX_IN_DELETE_SELF)

char buf[8192];

struct {
	uint32_t	mask;
	bool		cookie;
	char		name[16];
} target_events[] = {
	{ .mask = LINUX_IN_CREATE,	.cookie = 0,	.name = "test", },
	{ .mask = LINUX_IN_MOVED_FROM,	.cookie = 1,	.name = "test", },
	{ .mask = LINUX_IN_MOVED_TO,	.cookie = 1,	.name = "test2", },
	{ .mask = LINUX_IN_DELETE,	.cookie = 0,	.name = "test2", },
	{ .mask = LINUX_IN_MOVE_SELF,	.cookie = 0,	.name = "", },
	{ .mask = LINUX_IN_DELETE_SELF,	.cookie = 0,	.name = "", },
	{ .mask = LINUX_IN_IGNORED,	.cookie = 0,	.name = "", },
};

void
_start(void)
{
	int fd, wd, targetfd;
	char *cur_buf;
	struct linux_inotify_event *cur_ie;

	RS(mkdir("test", 0644));

	RS(fd = syscall(LINUX_SYS_inotify_init));
	RS(wd = syscall(LINUX_SYS_inotify_add_watch, fd, (register_t)"test",
	    INOTIFY_ALL_DIRECTORY));

	/* Create some events. */
	RS(targetfd = open("test/test", LINUX_O_RDWR|LINUX_O_CREAT, 0644));
	RS(write(targetfd, &targetfd, sizeof(targetfd)));
	RS(close(targetfd));
	RS(rename("test/test", "test/test2"));
	RS(unlink("test/test2"));
	RS(rename("test", "test2"));
	RS(rmdir("test2"));

	/* Check the events. */
	RS(read(fd, buf, sizeof(buf)));
	cur_buf = buf;
	for (size_t i = 0; i < __arraycount(target_events); i++) {
		cur_ie = (struct linux_inotify_event *)cur_buf;

		REQUIRE(cur_ie->wd == wd);
		REQUIRE(cur_ie->mask == target_events[i].mask);

		if (target_events[i].cookie)
			REQUIRE(cur_ie->cookie != 0);
		else
			REQUIRE(cur_ie->cookie == 0);

		if (target_events[i].name[0] != '\0') {
			REQUIRE(cur_ie->len > strlen(target_events[i].name));
			REQUIRE(strcmp(cur_ie->name, target_events[i].name) == 0);
		} else
			REQUIRE(cur_ie->len == 0);

		cur_buf += sizeof(struct linux_inotify_event) + cur_ie->len;
	}

	exit(0);
}
