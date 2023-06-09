/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bitops.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/vnode.h>

#include <sys/syscallargs.h>

#include <compat/linux/common/linux_machdep.h>
#include <compat/linux/common/linux_event.h>
#include <compat/linux/common/linux_fcntl.h>
#include <compat/linux/common/linux_sched.h>
#include <compat/linux/common/linux_signal.h>

#include <compat/linux/linux_syscallargs.h>

#define LINUX_EPOLL_MAX_EVENTS	(INT_MAX / sizeof(struct linux_epoll_event))
#define LINUX_EPOLL_MAX_DEPTH	5

#define kext_data	ext[0]
#define kext_epfd	ext[1]
#define kext_fd		ext[2]

#if DEBUG_LINUX
#define DPRINTF(x) uprintf x
#else
#define DPRINTF(x)
#endif

struct epoll_copyout_args {
	struct linux_epoll_event *leventlist;
	int			 count;
	int			 error;
};

struct epoll_edge {
	int epfd;
	int fd;
};

__BITMAP_TYPE(epoll_seen, char, 1);

static int	epoll_to_kevent(int epfd, int fd,
		    struct linux_epoll_event *l_event, struct kevent *kevent,
		    int *nkevents);
static void	kevent_to_epoll(struct kevent *kevent,
		    struct linux_epoll_event *l_event);
static int      epoll_kev_put_events(void *ctx, struct kevent *events,
		    struct kevent *eventlist, size_t index, int n);
static int	epoll_kev_fetch_changes(void *ctx, const struct kevent *changelist,
		    struct kevent *changes, size_t index, int n);
static int	epoll_kev_fetch_timeout(const void *src, void *dest, size_t size);
static int	epoll_wait_ts(struct lwp *l, register_t *retval, int epfd,
		    struct linux_epoll_event *events, int maxevents,
		    struct timespec *tsp, const linux_sigset_t *lssp);
static int	epoll_wait_common(struct lwp *l, register_t *retval,
		    int epfd, struct linux_epoll_event *events, int maxevents,
		    int timeout, const linux_sigset_t *lssp);
static int	epoll_register_kevent(register_t *retval, int epfd,
		    int fd, int filter, unsigned int flags);
static int	epoll_fd_registered(register_t *retval, int epfd,
		    int fd);
static int	epoll_delete_all_events(register_t *retval, int epfd,
		    int fd);
static int	epoll_recover_watch_tree(struct epoll_edge *edges,
		    size_t nedges, size_t nfds);
static int	epoll_dfs(struct epoll_edge *edges, size_t nedges,
		    struct epoll_seen *seen, size_t nseen, int currfd,
		    int depth);
static int	epoll_check_loop_and_depth(struct lwp *l, int epfd, int fd);

/*
 * epoll_create(2).  Just create a kqueue instance.
 */
int
linux_sys_epoll_create(struct lwp *l, const struct linux_sys_epoll_create_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) size;
	} */

	/*
	 * args->size is unused. Linux just tests it
	 * and then forgets it as well.
	 */
	if (SCARG(uap, size) <= 0)
		return EINVAL;

	return sys_kqueue(l, NULL, retval);
}

/*
 * epoll_create1(2).  Parse the flags and then create a kqueue instance.
 */
int
linux_sys_epoll_create1(struct lwp *l, const struct linux_sys_epoll_create1_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) flags;
	} */
	struct sys_kqueue1_args kqa;

	if ((SCARG(uap, flags) & ~(LINUX_O_CLOEXEC)) != 0)
		return EINVAL;

	SCARG(&kqa, flags) = 0;
	if ((SCARG(uap, flags) & LINUX_O_CLOEXEC) != 0)
		SCARG(&kqa, flags) |= O_CLOEXEC;

	return sys_kqueue1(l, &kqa, retval);
}

/*
 * Structure converting function from epoll to kevent.
 */
static int
epoll_to_kevent(int epfd, int fd, struct linux_epoll_event *l_event,
    struct kevent *kevent, int *nkevents)
{
	uint32_t levents = l_event->events;
	uint32_t kev_flags = EV_ADD | EV_ENABLE;

	/* flags related to how event is registered */
	if ((levents & LINUX_EPOLLONESHOT) != 0)
		kev_flags |= EV_DISPATCH;
	if ((levents & LINUX_EPOLLET) != 0)
		kev_flags |= EV_CLEAR;
	if ((levents & LINUX_EPOLLERR) != 0)
		kev_flags |= EV_ERROR;
	if ((levents & LINUX_EPOLLRDHUP) != 0)
		kev_flags |= EV_EOF;

	/* flags related to what event is registered */
	if ((levents & LINUX_EPOLL_EVRD) != 0) {
		EV_SET(kevent, fd, EVFILT_READ, kev_flags, 0, 0, 0);
		kevent->kext_data = l_event->data;
		kevent->kext_epfd = epfd;
		kevent->kext_fd = fd;
		++kevent;
		++(*nkevents);
	}
	if ((levents & LINUX_EPOLL_EVWR) != 0) {
		EV_SET(kevent, fd, EVFILT_WRITE, kev_flags, 0, 0, 0);
		kevent->kext_data = l_event->data;
		kevent->kext_epfd = epfd;
		kevent->kext_fd = fd;
		++kevent;
		++(*nkevents);
	}
	/* zero event mask is legal */
	if ((levents & (LINUX_EPOLL_EVRD | LINUX_EPOLL_EVWR)) == 0) {
		EV_SET(kevent++, fd, EVFILT_READ, EV_ADD|EV_DISABLE, 0, 0, 0);
		++(*nkevents);
	}

	if ((levents & ~(LINUX_EPOLL_EVSUP)) != 0) {
		return EINVAL;
	}

	return 0;
}

/*
 * Structure converting function from kevent to epoll. In a case
 * this is called on error in registration we store the error in
 * event->data and pick it up later in linux_sys_epoll_ctl().
 */
static void
kevent_to_epoll(struct kevent *kevent, struct linux_epoll_event *l_event)
{

	l_event->data = kevent->kext_data;

	if ((kevent->flags & EV_ERROR) != 0) {
		l_event->events = LINUX_EPOLLERR;
		return;
	}

	/* XXX EPOLLPRI, EPOLLHUP */
	switch (kevent->filter) {
	case EVFILT_READ:
		l_event->events = LINUX_EPOLLIN;
		if ((kevent->flags & EV_EOF) != 0)
			l_event->events |= LINUX_EPOLLRDHUP;
		break;
	case EVFILT_WRITE:
		l_event->events = LINUX_EPOLLOUT;
		break;
	default:
		DPRINTF(("kevent_to_epoll: unhandled kevent filter %d\n",
		    kevent->filter));
		break;
	}
}

/*
 * Copyout callback used by kevent. This converts kevent
 * events to epoll events and copies them back to the
 * userspace. This is also called on error on registering
 * of the filter.
 */
static int
epoll_kev_put_events(void *ctx, struct kevent *events,
    struct kevent *eventlist, size_t index, int n)
{
	struct epoll_copyout_args *args;
	struct linux_epoll_event *eep;
	int error, i;
	size_t levent_size = sizeof(*eep) * n;

	KASSERT(n >= 0 && n < LINUX_EPOLL_MAX_EVENTS);

	args = (struct epoll_copyout_args *)ctx;
	eep = kmem_alloc(levent_size, KM_SLEEP);

	for (i = 0; i < n; i++)
		kevent_to_epoll(events + index + i, eep + i);

	error = copyout(eep, args->leventlist, levent_size);
	if (error == 0) {
		args->leventlist += n;
		args->count += n;
	} else if (args->error == 0)
		args->error = error;

	kmem_free(eep, levent_size);
	return error;
}

/*
 * Copyin callback used by kevent. This copies already
 * converted filters from kernel memory to the kevent
 * internal kernel memory. Hence the memcpy instead of
 * copyin.
 */
static int
epoll_kev_fetch_changes(void *ctx, const struct kevent *changelist,
    struct kevent *changes, size_t index, int n)
{
	KASSERT(n >= 0 && n < LINUX_EPOLL_MAX_EVENTS);

	memcpy(changes, changelist + index, n * sizeof(*changes));

	return 0;
}

/*
 * Timer copy callback used by kevent.  Copies a converted timeout
 * from kernel memory to kevent memory.  Hence the memcpy instead of
 * just using copyin.
 */
static int
epoll_kev_fetch_timeout(const void *src, void *dest, size_t size)
{
	memcpy(dest, src, size);

	return 0;
}

/*
 * Load epoll filter, convert it to kevent filter
 * and load it into kevent subsystem.
 */
int
linux_sys_epoll_ctl(struct lwp *l, const struct linux_sys_epoll_ctl_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) epfd;
		syscallarg(int) op;
		syscallarg(int) fd;
		syscallarg(struct linux_epoll_event *) event;
	} */
	struct kevent kev[2];
	struct linux_epoll_event le;
        struct kevent_ops k_ops = {
		.keo_private = NULL,
		.keo_fetch_timeout = NULL,
		.keo_fetch_changes = epoll_kev_fetch_changes,
		.keo_put_events = NULL,
	};
	file_t *epfp, *fp;
	int error = 0;
	int nchanges = 0;
	const int epfd = SCARG(uap, epfd);
	const int op = SCARG(uap, op);
	const int fd = SCARG(uap, fd);

	if (op != LINUX_EPOLL_CTL_DEL) {
		error = copyin(SCARG(uap, event), &le, sizeof(le));
		if (error != 0)
			return error;
	}

	/* Need to validate epfd and fd separately from kevent1 to match
	   Linux's errno behaviour. */
	epfp = fd_getfile(epfd);
	if (epfp == NULL)
		return EBADF;
	if (epfp->f_type != DTYPE_KQUEUE)
		error = EINVAL;
	fd_putfile(epfd);
	if (error != 0)
		return error;

	fp = fd_getfile(fd);
	if (fp == NULL)
		return EBADF;
	if (fp->f_type == DTYPE_VNODE) {
		switch (fp->f_vnode->v_type) {
		case VREG:
		case VDIR:
		case VBLK:
		case VLNK:
			error = EPERM;
			break;

		default:
			break;
		}
	}
	fd_putfile(fd);
	if (error != 0)
		return error;

	/* Linux disallows spying on himself */
	if (epfd == fd) {
		return EINVAL;
	}

	if (op != LINUX_EPOLL_CTL_DEL) {
		error = epoll_to_kevent(epfd, fd, &le, kev, &nchanges);
		if (error != 0)
			return error;
	}

	switch (op) {
	case LINUX_EPOLL_CTL_MOD:
		error = epoll_delete_all_events(retval, epfd, fd);
		if (error != 0)
			return error;
		break;

	case LINUX_EPOLL_CTL_ADD:
		if (epoll_fd_registered(retval, epfd, fd))
			return EEXIST;
		error = epoll_check_loop_and_depth(l, epfd, fd);
		if (error != 0)
			return error;
		break;

	case LINUX_EPOLL_CTL_DEL:
		/* CTL_DEL means unregister this fd with this epoll */
		return epoll_delete_all_events(retval, epfd, fd);

	default:
		DPRINTF(("linux_sys_epoll_ctl: invalid op %d\n", op));
		return EINVAL;
	}

	error = kevent1(retval, epfd, kev, nchanges, NULL, 0, NULL, &k_ops);

	if (error == EOPNOTSUPP) {
		error = EPERM;
	}

	return error;
}

/*
 * Wait for a filter to be triggered on the epoll file descriptor.
 * All of the epoll_*wait* syscalls eventually end up here.
 */
static int
epoll_wait_ts(struct lwp *l, register_t *retval, int epfd,
    struct linux_epoll_event *events, int maxevents, struct timespec *tsp,
    const linux_sigset_t *lssp)
{
	struct epoll_copyout_args coargs;
	struct kevent_ops k_ops = {
	        .keo_private = &coargs,
		.keo_fetch_timeout = epoll_kev_fetch_timeout,
		.keo_fetch_changes = NULL,
		.keo_put_events = epoll_kev_put_events,
	};
	struct proc *p = l->l_proc;
	file_t *epfp;
	sigset_t nss, oss;
	linux_sigset_t lss;
	int error = 0;

	if (maxevents <= 0 || maxevents > LINUX_EPOLL_MAX_EVENTS)
		return EINVAL;

	/* Need to validate epfd separately from kevent1 to match
	   Linux's errno behaviour. */
	epfp = fd_getfile(epfd);
	if (epfp == NULL)
		return EBADF;
	if (epfp->f_type != DTYPE_KQUEUE)
		error = EINVAL;
	fd_putfile(epfd);
	if (error != 0)
		return error;

	if (lssp != NULL) {
		error = copyin(lssp, &lss, sizeof(lss));
		if (error != 0)
			return error;
		
		linux_to_native_sigset(&nss, &lss);

		mutex_enter(p->p_lock);
		error = sigprocmask1(l, SIG_SETMASK, &nss, &oss);
		mutex_exit(p->p_lock);
		if (error != 0)
			return error;
	}

	coargs.leventlist = events;
	coargs.count = 0;
	coargs.error = 0;

	error = kevent1(retval, epfd, NULL, 0, NULL, maxevents, tsp, &k_ops);
	if (error == 0 && coargs.error != 0)
		error = coargs.error;

	/*
	 * kern_kevent might return ENOMEM which is not expected from epoll_wait.
	 * Maybe we should translate that but I don't think it matters at all.
	 */
	if (error == 0)
		*retval = coargs.count;

	if (lssp != NULL) {
	        mutex_enter(p->p_lock);
		error = sigprocmask1(l, SIG_SETMASK, &oss, NULL);
		mutex_exit(p->p_lock);
	}

	return error;
}

/*
 * Convert timeout to a timespec and then call epoll_wait_ts.
 */
static int
epoll_wait_common(struct lwp *l, register_t *retval, int epfd,
    struct linux_epoll_event *events, int maxevents, int timeout,
    const linux_sigset_t *lssp)
{
	struct timespec ts, *tsp;

	/*
	 * Linux epoll_wait(2) man page states that timeout of -1 causes caller
	 * to block indefinitely. Real implementation does it if any negative
	 * timeout value is passed.
	 */
	if (timeout >= 0) {
		/* Convert from milliseconds to timespec. */
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	} else {
		tsp = NULL;
	}
	return epoll_wait_ts(l, retval, epfd, events, maxevents, tsp, lssp);
}

/*
 * epoll_wait(2).
 */
int
linux_sys_epoll_wait(struct lwp *l, const struct linux_sys_epoll_wait_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) epfd;
		syscallarg(struct linux_epoll_event *) events;
		syscallarg(int) maxevents;
		syscallarg(int) timeout;
	} */

	return epoll_wait_common(l, retval, SCARG(uap, epfd), SCARG(uap, events),
	    SCARG(uap, maxevents), SCARG(uap, timeout), NULL);
}

/*
 * epoll_pwait(2).
 */
int
linux_sys_epoll_pwait(struct lwp *l, const struct linux_sys_epoll_pwait_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) epfd;
		syscallarg(struct linux_epoll_event *) events;
		syscallarg(int) maxevents;
		syscallarg(int) timeout;
		syscallarg(linux_sigset_t *) sigmask;
	} */

	return epoll_wait_common(l, retval, SCARG(uap, epfd), SCARG(uap, events),
	    SCARG(uap, maxevents), SCARG(uap, timeout), SCARG(uap, sigmask));
}

/*
 * epoll_pwait2(2).
 */
int
linux_sys_epoll_pwait2(struct lwp *l, const struct linux_sys_epoll_pwait2_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) epfd;
		syscallarg(struct linux_epoll_event *) events;
		syscallarg(int) maxevents;
		syscallarg(struct linux_timespec *) timeout;
		syscallarg(linux_sigset_t *) sigmask;
	} */
	struct timespec ts, *tsp;
	struct linux_timespec lts;
	int error;

	if (SCARG(uap, timeout) != NULL) {
		error = copyin(SCARG(uap, timeout), &lts, sizeof(lts));
		if (error != 0)
			return error;

		linux_to_native_timespec(&ts, &lts);
		tsp = &ts;
	} else
		tsp = NULL;

	return epoll_wait_ts(l, retval, SCARG(uap, epfd),
	    SCARG(uap, events), SCARG(uap, maxevents), tsp,
	    SCARG(uap, sigmask));
}

/*
 * Helper that registers a single kevent.
 */
static int
epoll_register_kevent(register_t *retval, int epfd, int fd, int filter,
    unsigned int flags)
{
	struct kevent kev;
	struct kevent_ops k_ops = {
		.keo_private = NULL,
		.keo_fetch_timeout = NULL,
		.keo_fetch_changes = epoll_kev_fetch_changes,
		.keo_put_events = NULL,
	};

	EV_SET(&kev, fd, filter, flags, 0, 0, 0);

        return kevent1(retval, epfd, &kev, 1, NULL, 0, NULL, &k_ops);
}

/*
 * Check if an fd is already registered in the kqueue referenced by epfd.
 */
static int
epoll_fd_registered(register_t *retval, int epfd, int fd)
{
	/*
	 * Set empty filter flags to avoid accidental modification of already
	 * registered events. In the case of event re-registration:
	 * 1. If event does not exists kevent() does nothing and returns ENOENT
	 * 2. If event does exists, it's enabled/disabled state is preserved
	 *    but fflags, data and udata fields are overwritten. So we can not
	 *    set socket lowats and store user's context pointer in udata.
	 */
	if (epoll_register_kevent(retval, epfd, fd, EVFILT_READ, 0) != ENOENT ||
	    epoll_register_kevent(retval, epfd, fd, EVFILT_WRITE, 0) != ENOENT)
		return 1;

	return 0;
}

/*
 * Remove all events in the kqueue referenced by epfd that depend on
 * fd.
 */
static int
epoll_delete_all_events(register_t *retval, int epfd, int fd)
{
	int error1, error2;

	error1 = epoll_register_kevent(retval, epfd, fd, EVFILT_READ, EV_DELETE);
	error2 = epoll_register_kevent(retval, epfd, fd, EVFILT_WRITE, EV_DELETE);

	/* return 0 if at least one result positive */
	return error1 == 0 ? 0 : error2;
}

/*
 * Interate through all the knotes and recover a directed graph on
 * which kqueues are watching each other.
 *
 * If edges is NULL, the number of edges is still counted but no graph
 * is assembled.
 */
static int
epoll_recover_watch_tree(struct epoll_edge *edges, size_t nedges, size_t nfds) {
	file_t *currfp, *targetfp;
	struct knote *kn, *tmpkn;
	size_t i, nedges_so_far = 0;

	for (i = 0; i < nfds && (edges == NULL || nedges_so_far < nedges); i++) {
		currfp = fd_getfile(i);
		if (currfp == NULL)
			continue;
		if (currfp->f_type != DTYPE_KQUEUE)
			goto continue_count_outer;

		SLIST_FOREACH_SAFE(kn, &currfp->f_kqueue->kq_sel.sel_klist,
		    kn_selnext, tmpkn) {
			targetfp = fd_getfile(kn->kn_kevent.kext_epfd);
			if (targetfp == NULL)
				continue;
			if (targetfp->f_type == DTYPE_KQUEUE) {
				if (edges != NULL) {
					edges[nedges_so_far].epfd = kn->kn_kevent.kext_epfd;
					edges[nedges_so_far].fd = kn->kn_kevent.kext_fd;
				}
				nedges_so_far++;
			}

			fd_putfile(kn->kn_kevent.kext_epfd);
		}

        continue_count_outer:
		fd_putfile(i);
	}

	return nedges_so_far;
}

/*
 * Run dfs on the graph described by edges, checking for loops and a
 * depth greater than LINUX_EPOLL_MAX_DEPTH.
 */
static int
epoll_dfs(struct epoll_edge *edges, size_t nedges, struct epoll_seen *seen,
    size_t nseen, int currfd, int depth) {
	int error;
	size_t i;

	KASSERT(edges != NULL);
	KASSERT(seen != NULL);
	KASSERT(nedges > 0);
	KASSERT(currfd < nseen);
	KASSERT(0 <= depth && depth <= LINUX_EPOLL_MAX_DEPTH + 1);

	if (__BITMAP_ISSET(currfd, seen))
		return ELOOP;

	__BITMAP_SET(currfd, seen);

	depth++;
	if (depth > LINUX_EPOLL_MAX_DEPTH)
		return EINVAL;

	for (i = 0; i < nedges; i++) {
		if (edges[i].epfd != currfd)
			continue;

		error = epoll_dfs(edges, nedges, seen, nseen,
		    edges[i].fd, depth);
		if (error != 0)
			return error;
	}

	return 0;
}

/*
 * Check if adding fd to epfd would violate the maximum depth or
 * create a loop.
 */
static int
epoll_check_loop_and_depth(struct lwp *l, int epfd, int fd)
{
	int error;
	file_t *fp;
	struct epoll_edge *edges;
	struct epoll_seen *seen;
	size_t nedges, nfds, seen_size;
	bool fdirrelevant;

	/* If the target isn't another kqueue, we can skip this check */
	fp = fd_getfile(fd);
	if (fp == NULL)
		return 0;
	fdirrelevant = fp->f_type != DTYPE_KQUEUE;
	fd_putfile(fd);
	if (fdirrelevant)
		return 0;

	nfds = l->l_proc->p_fd->fd_lastfile + 1;

	/* We call epoll_recover_watch_tree twice, once to find the
	   number of edges, and once to actually fill them in.  We add one
	   because we want to include the edge epfd->fd. */
        nedges = 1 + epoll_recover_watch_tree(NULL, 0, nfds);

	edges = kmem_zalloc(nedges * sizeof(*edges), KM_SLEEP);

	epoll_recover_watch_tree(edges + 1, nedges - 1, nfds);

	edges[0].epfd = epfd;
	edges[0].fd = fd;

	seen_size = __BITMAP_SIZE(char, nfds);
	seen = kmem_zalloc(seen_size, KM_SLEEP);

	error = epoll_dfs(edges, nedges, seen, nfds, epfd, 0);

	kmem_free(seen, seen_size);
	kmem_free(edges, nedges * sizeof(*edges));

	return error;
}
