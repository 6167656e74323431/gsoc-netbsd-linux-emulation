#ifndef	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_
#define	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_

#define _STANDALONE
#include <sys/types.h>
#undef _STANDALONE

#define	syscall(number, ...)	syscall6(number, ## __VA_ARGS__, \
				    0, 0, 0, 0, 0, 0)

#define	RS(x)			if ((x) == -1) exit(errno);

extern int errno;

long	syscall6(long number, register_t, register_t, register_t, register_t,
	    register_t, register_t, ...);

/* Convinience wrappers. */
void	exit(int status);
int	fcntl(int fd, int cmd, ...);

#endif /* !SRC_TESTS_COMPAT_LINUX_H_LINUX_H_ */
