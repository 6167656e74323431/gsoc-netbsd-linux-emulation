/*-
 * Copyright (c) 2007 Roman Divacky
 * Copyright (c) 2014 Dmitry Chagin <dchagin@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _SYS_EPOLL_H_
#define	_SYS_EPOLL_H_

#include <sys/types.h>			/* for uint32_t, uint64_t */
#include <sys/sigtypes.h>		/* for sigset_t */
#include <sys/time.h>			/* for struct timespec */

#define	EPOLLIN		0x001
#define	EPOLLPRI	0x002
#define	EPOLLOUT	0x004
#define	EPOLLRDNORM	0x040
#define	EPOLLRDBAND	0x080
#define	EPOLLWRNORM	0x100
#define	EPOLLWRBAND	0x200
#define	EPOLLMSG	0x400
#define	EPOLLERR	0x008
#define	EPOLLHUP	0x010
#define	EPOLLRDHUP	0x2000
#define	EPOLLWAKEUP	1u<<29
#define	EPOLLONESHOT	1u<<30
#define	EPOLLET		1u<<31

#define	EPOLL_CTL_ADD	1
#define	EPOLL_CTL_DEL	2
#define	EPOLL_CTL_MOD	3

#ifdef _KERNEL
typedef uint64_t		epoll_data_t;
#else
union epoll_data {
	void		*ptr;
	int		fd;
	uint32_t	u32;
	uint64_t	u64;
};

typedef union epoll_data	epoll_data_t;
#endif

struct epoll_event {
	uint32_t	events;
	epoll_data_t	data;
}
#if defined(__amd64__)
__attribute__((packed))
#endif
;

#ifdef _KERNEL
int	epoll_wait_common(struct lwp *l, register_t *retval, int epfd,
	    struct epoll_event *events, int maxevents, struct timespec *tsp,
	    const sigset_t *nss);
#else	/* !_KERNEL */
__BEGIN_DECLS
#ifdef _NETBSD_SOURCE
int	epoll_create(int size);
int	epoll_create1(int flags);
int	epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int	epoll_wait(int epfd, struct epoll_event *events, int maxevents,
	    int timeout);
int	epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
	    int timeout, const sigset_t *sigmask);
int	epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
	    const struct timespec *timeout, const sigset_t *sigmask);
#endif	/* _NETBSD_SOURCE */
__END_DECLS
#endif	/* !_KERNEL */

#endif	/* !_SYS_EPOLL_H_ */
