#include "h_linux.h"

#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_inotify.h>

struct linux_inotify_event events[2];

void
_start(void)
{
	int fd, wd, targetfd;
	ssize_t nread;

	RS(targetfd = open("test", LINUX_O_RDWR|LINUX_O_CREAT, 0644));
	RS(close(targetfd));

	RS(fd = syscall(LINUX_SYS_inotify_init));
	RS(wd = syscall(LINUX_SYS_inotify_add_watch, fd, (register_t)"test",
            LINUX_IN_CLOSE_NOWRITE));

	/* We should only get the close event. */
	RS(targetfd = open("test", LINUX_O_RDONLY|LINUX_O_CREAT, 0644));
	RS(close(targetfd));

	RS(nread = read(fd, events, sizeof(events)));
	REQUIRE(nread == sizeof(events[0]));
	REQUIRE(events[0].mask == LINUX_IN_CLOSE_NOWRITE);

	/* Change the watch descriptor. */
	RS(wd = syscall(LINUX_SYS_inotify_add_watch, fd, (register_t)"test",
	    LINUX_IN_OPEN));

	/* We should only get the open event. */
	RS(targetfd = open("test", LINUX_O_RDONLY|LINUX_O_CREAT, 0644));
	RS(close(targetfd));

	RS(nread = read(fd, events, sizeof(events)));
	REQUIRE(nread == sizeof(events[0]));
	REQUIRE(events[0].mask == LINUX_IN_OPEN);

	/* Add to the watch descriptor. */
	RS(wd = syscall(LINUX_SYS_inotify_add_watch, fd, (register_t)"test",
	    LINUX_IN_CLOSE_NOWRITE|LINUX_IN_MASK_ADD));

	/* Now we should get both the open and the close. */
	RS(targetfd = open("test", LINUX_O_RDONLY|LINUX_O_CREAT, 0644));
	RS(close(targetfd));

	RS(nread = read(fd, events, sizeof(events)));
	REQUIRE(nread == 2 * sizeof(events[0]));
	REQUIRE(events[0].mask == LINUX_IN_OPEN);
	REQUIRE(events[1].mask == LINUX_IN_CLOSE_NOWRITE);

	exit(0);
}
