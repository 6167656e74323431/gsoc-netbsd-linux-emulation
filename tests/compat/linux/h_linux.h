#ifndef	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_
#define	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_

#define _STANDALONE
#include <sys/types.h>	/* For register_t. */
#undef _STANDALONE

#define	FAIL			(-1)

#define	syscall(number, ...)	syscall6(number, ## __VA_ARGS__, \
				    0, 0, 0, 0, 0, 0)

#define	RS(x)			do { if ((x) == -1) exit(errno); } while (0)
#define	REQUIRE(x)		do { if (!(x)) exit(FAIL); } while (0)

/* Convinience wrappers for common syscalls. */
#define	close(fd)		(int)syscall(LINUX_SYS_close, fd)
#define	exit(status)		(void)syscall(LINUX_SYS_exit_group, status)
#define	fcntl(fd, cmd, ...)	(int)syscall(LINUX_SYS_fcntl, fd, cmd, \
			            ## __VA_ARGS__)
#define	lseek(fd, off, whence)	(off_t)syscall(LINUX_SYS_lseek, fd, \
				    (register_t)off, whence)
#define	mkdir(path, mode)	(int)syscall(LINUX_SYS_mkdir, \
				    (register_t)path, mode)
#define	open(path, flags, ...)	(int)syscall(LINUX_SYS_open, \
				    (register_t)path, flags, \
				    ## __VA_ARGS__)
#define	read(fd, buf, count)	(ssize_t)syscall(LINUX_SYS_read, fd, \
				    (register_t)buf, count)
#define	rename(from, to)	(int)syscall(LINUX_SYS___posix_rename, \
				    (register_t)from, (register_t)to)
#define	rmdir(path)		(int)syscall(LINUX_SYS_rmdir, \
				    (register_t)path)
#define	unlink(path)		(int)syscall(LINUX_SYS_unlink, \
				    (register_t)path)
#define	write(fd, buf, count)	(ssize_t)syscall(LINUX_SYS_write, fd, \
				    (register_t)buf, count)

/* GCC builtins. */
#define	strcmp(s1, s2)		__builtin_strcmp(s1, s2)
#define	strlen(s)		__builtin_strlen(s)

long	syscall6(long number, register_t, register_t, register_t, register_t,
	    register_t, register_t, ...);

extern int errno;

#endif /* !SRC_TESTS_COMPAT_LINUX_H_LINUX_H_ */
