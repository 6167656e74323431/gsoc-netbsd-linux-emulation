#include "h_linux.h"

#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_inotify.h>

#define	INOTIFY_ALL_FILE	(LINUX_IN_ATTRIB|LINUX_IN_CLOSE_NOWRITE \
				|LINUX_IN_OPEN|LINUX_IN_MOVE_SELF \
				|LINUX_IN_ACCESS|LINUX_IN_CLOSE_WRITE \
				|LINUX_IN_MODIFY)

struct linux_inotify_event events[7];

void
_start(void)
{
	int fd, wd, targetfd, buf;

	RS(targetfd = open("test", LINUX_O_RDWR|LINUX_O_CREAT, 0644));
	RS(close(targetfd));

	RS(fd = syscall(LINUX_SYS_inotify_init));
	RS(wd = syscall(LINUX_SYS_inotify_add_watch, fd, (register_t)"test",
            INOTIFY_ALL_FILE));

	/* Create some events. */
	RS(targetfd = open("test", LINUX_O_RDWR|LINUX_O_CREAT, 0644));
	RS(write(targetfd, &buf, sizeof(buf)));
	RS(read(targetfd, &buf, sizeof(buf)));
	RS(close(targetfd));
	RS(targetfd = open("test", LINUX_O_RDONLY|LINUX_O_CREAT, 0644));
	RS(close(targetfd));
	RS(rename("test", "test2"));

	/* Get and check the events. */
	RS(read(fd, events, sizeof(events)));

	for (size_t i = 0; i < __arraycount(events); i++)
		REQUIRE(events[i].wd == wd && events[i].cookie == 0
		    && events[i].len == 0);

	REQUIRE(events[0].mask == LINUX_IN_OPEN);
	REQUIRE(events[1].mask == LINUX_IN_MODIFY);
	REQUIRE(events[2].mask == LINUX_IN_ACCESS);
	REQUIRE(events[3].mask == LINUX_IN_CLOSE_WRITE);
	REQUIRE(events[4].mask == LINUX_IN_OPEN);
	REQUIRE(events[5].mask == LINUX_IN_CLOSE_NOWRITE);
	REQUIRE(events[6].mask == LINUX_IN_MOVE_SELF);

	exit(0);
}
