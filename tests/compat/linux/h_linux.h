#ifndef	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_
#define	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_

#define _STANDALONE
#include <sys/types.h>	/* For register_t. */
#undef _STANDALONE

#define	syscall(number, ...)	syscall6(number, ## __VA_ARGS__, \
				    0, 0, 0, 0, 0, 0)

#define	RS(x)			if ((x) == -1) exit(errno);

/* Convinience wrappers. */
#define	close(fd)		(int)syscall(LINUX_SYS_close, fd)
#define	exit(status)		(void)syscall(LINUX_SYS_exit_group, status)
#define	fcntl(fd, cmd, ...)	(int)syscall(LINUX_SYS_fcntl, fd, cmd, \
					    ## __VA_ARGS__)

long	syscall6(long number, register_t, register_t, register_t, register_t,
	    register_t, register_t, ...);

extern int errno;

#endif /* !SRC_TESTS_COMPAT_LINUX_H_LINUX_H_ */
