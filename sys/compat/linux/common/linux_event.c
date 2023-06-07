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
#include <sys/event.h>
#include <sys/errno.h>
#include <sys/fcntl.h>

#include <sys/syscallargs.h>

#include <compat/linux/common/linux_machdep.h>
#include <compat/linux/common/linux_event.h>
#include <compat/linux/common/linux_fcntl.h>

#include <compat/linux/linux_syscallargs.h>

#define	LINUX_MAX_EVENTS	(INT_MAX / sizeof(struct epoll_event))

static int	epoll_to_kevent(int fd,
		    struct linux_epoll_event *l_event, struct kevent *kevent,
		    int *nkevents);
//static void	kevent_to_epoll(struct kevent *kevent,
//		    struct linux_epoll_event *l_event);
//static int	epoll_kev_copyout(void *arg, struct kevent *kevp, int count);
static int	epoll_kev_copyin(void *ctx, const struct kevent *changelist,
		    struct kevent *changes, size_t index, int n);
static int	epoll_register_kevent(register_t *retval, int epfd,
		    int fd, int filter, unsigned int flags);
static int	epoll_fd_registered(register_t *retval, int epfd,
		    int fd);
static int	epoll_delete_all_events(register_t *retval, int epfd,
		    int fd);

struct epoll_copyout_args {
	struct epoll_event	*leventlist;
	struct proc		*p;
	uint32_t		count;
	int			error;
};

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
		return (EINVAL);

	return sys_kqueue(l, NULL, retval);
}

int
linux_sys_epoll_create1(struct lwp *l, const struct linux_sys_epoll_create1_args *uap, register_t *retval)
{
	/* {
		syscallarg(int) flags;
	} */
	struct sys_kqueue1_args kqa;

	if ((SCARG(uap, flags) & ~(LINUX_O_CLOEXEC)) != 0)
		return (EINVAL);

	SCARG(&kqa, flags) = 0;
	if ((SCARG(uap, flags) & LINUX_O_CLOEXEC) != 0)
		SCARG(&kqa, flags) |= O_CLOEXEC;

	return sys_kqueue1(l, &kqa, retval);
}

/* Structure converting function from epoll to kevent. */
static int
epoll_to_kevent(int fd, struct linux_epoll_event *l_event,
    struct kevent *kevent, int *nkevents)
{
	uint32_t levents = l_event->events;
	unsigned short kev_flags = EV_ADD | EV_ENABLE;

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
//		kevent->ext[0] = l_event->data;
		++kevent;
		++(*nkevents);
	}
	if ((levents & LINUX_EPOLL_EVWR) != 0) {
		EV_SET(kevent, fd, EVFILT_WRITE, kev_flags, 0, 0, 0);
//		kevent->ext[0] = l_event->data;
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

	return (0);
}
#if 0
/*
 * Structure converting function from kevent to epoll. In a case
 * this is called on error in registration we store the error in
 * event->data and pick it up later in linux_epoll_ctl().
 */
static void
kevent_to_epoll(struct kevent *kevent, struct linux_epoll_event *l_event)
{

	l_event->data = kevent->ext[0];

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
	}
}

/*
 * Copyout callback used by kevent. This converts kevent
 * events to epoll events and copies them back to the
 * userspace. This is also called on error on registering
 * of the filter.
 */
static int
epoll_kev_copyout(void *arg, struct kevent *kevp, int count)
{
	struct epoll_copyout_args *args;
	struct epoll_event *eep;
	int error, i;

	args = (struct epoll_copyout_args*) arg;
	eep = malloc(sizeof(*eep) * count, M_EPOLL, M_WAITOK | M_ZERO);

	for (i = 0; i < count; i++)
		kevent_to_epoll(&kevp[i], &eep[i]);

	error = copyout(eep, args->leventlist, count * sizeof(*eep));
	if (error == 0) {
		args->leventlist += count;
		args->count += count;
	} else if (args->error == 0)
		args->error = error;

	free(eep, M_EPOLL);
	return (error);
}
#endif
/*
 * Copyin callback used by kevent. This copies already
 * converted filters from kernel memory to the kevent
 * internal kernel memory. Hence the memcpy instead of
 * copyin.
 */
static int
epoll_kev_copyin(void *ctx, const struct kevent *changelist,
    struct kevent *changes, size_t index, int n)
{
	memcpy(changes, changelist + index, n * sizeof(*changes));

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
		.keo_fetch_changes = epoll_kev_copyin,
		.keo_put_events = NULL,
	};
	int error, nchanges = 0;
	const int epfd = SCARG(uap, epfd);
	const int op = SCARG(uap, op);
	const int fd = SCARG(uap, fd);

	if (op != LINUX_EPOLL_CTL_DEL) {
		error = copyin(SCARG(uap, event), &le, sizeof(le));
		if (error != 0)
			return (error);
	}

	// TODO: check validity of epfd
	// TODO: check validity of fd

	/* Linux disallows spying on himself */
	if (epfd == fd) {
		return EINVAL;
	}

	if (op != LINUX_EPOLL_CTL_DEL) {
		error = epoll_to_kevent(fd, &le, kev, &nchanges);
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
		if (epoll_fd_registered(retval, epfd, fd)) {
			return EEXIST;
		}
		break;

	case LINUX_EPOLL_CTL_DEL:
		/* CTL_DEL means unregister this fd with this epoll */
		return epoll_delete_all_events(retval, epfd, fd);

	default:
		return EINVAL;
	}

	error = kevent1(retval, SCARG(uap, epfd), kev, nchanges, NULL, 0, NULL, &k_ops);

	return (error);
}
#if 0
/*
 * Wait for a filter to be triggered on the epoll file descriptor.
 */

static int
linux_epoll_wait_ts(struct thread *td, int epfd, struct epoll_event *events,
    int maxevents, struct timespec *tsp, sigset_t *uset)
{
	struct epoll_copyout_args coargs;
	struct kevent_copyops k_ops = { &coargs,
					epoll_kev_copyout,
					NULL};
	cap_rights_t rights;
	struct file *epfp;
	sigset_t omask;
	int error;

	if (maxevents <= 0 || maxevents > LINUX_MAX_EVENTS)
		return (EINVAL);

	error = fget(td, epfd,
	    cap_rights_init_one(&rights, CAP_KQUEUE_EVENT), &epfp);
	if (error != 0)
		return (error);
	if (epfp->f_type != DTYPE_KQUEUE) {
		error = EINVAL;
		goto leave;
	}
	if (uset != NULL) {
		error = kern_sigprocmask(td, SIG_SETMASK, uset,
		    &omask, 0);
		if (error != 0)
			goto leave;
		td->td_pflags |= TDP_OLDMASK;
		/*
		 * Make sure that ast() is called on return to
		 * usermode and TDP_OLDMASK is cleared, restoring old
		 * sigmask.
		 */
		ast_sched(td, TDA_SIGSUSPEND);
	}

	coargs.leventlist = events;
	coargs.p = td->td_proc;
	coargs.count = 0;
	coargs.error = 0;

	error = kern_kevent_fp(td, epfp, 0, maxevents, &k_ops, tsp);
	if (error == 0 && coargs.error != 0)
		error = coargs.error;

	/*
	 * kern_kevent might return ENOMEM which is not expected from epoll_wait.
	 * Maybe we should translate that but I don't think it matters at all.
	 */
	if (error == 0)
		td->td_retval[0] = coargs.count;

	if (uset != NULL)
		error = kern_sigprocmask(td, SIG_SETMASK, &omask,
		    NULL, 0);
leave:
	fdrop(epfp, td);
	return (error);
}

static int
linux_epoll_wait_common(struct thread *td, int epfd, struct epoll_event *events,
    int maxevents, int timeout, sigset_t *uset)
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
	return (linux_epoll_wait_ts(td, epfd, events, maxevents, tsp, uset));

}

int
linux_sys_epoll_wait(struct thread *td, struct linux_epoll_wait_args *args)
{

	return (linux_epoll_wait_common(td, args->epfd, args->events,
	    args->maxevents, args->timeout, NULL));
}

int
linux_sys_epoll_pwait(struct thread *td, struct linux_epoll_pwait_args *args)
{
	sigset_t mask, *pmask;
	int error;

	error = linux_copyin_sigset(td, args->mask, sizeof(l_sigset_t),
	    &mask, &pmask);
	if (error != 0)
		return (error);

	return (linux_epoll_wait_common(td, args->epfd, args->events,
	    args->maxevents, args->timeout, pmask));
}

int
linux_sys_epoll_pwait2(struct thread *td, struct linux_epoll_pwait2_args *args)
{
	struct timespec ts, *tsa;
	sigset_t mask, *pmask;
	int error;

	error = linux_copyin_sigset(td, args->mask, sizeof(l_sigset_t),
	    &mask, &pmask);
	if (error != 0)
		return (error);

	if (args->timeout) {
		error = linux_get_timespec(&ts, args->timeout);
		if (error != 0)
			return (error);
		tsa = &ts;
	} else
		tsa = NULL;

	return (linux_epoll_wait_ts(td, args->epfd, args->events,
	    args->maxevents, tsa, pmask));
}
#endif
static int
epoll_register_kevent(register_t *retval, int epfd, int fd, int filter,
    unsigned int flags)
{
	struct kevent kev;
	struct kevent_ops k_ops = {
		.keo_private = NULL,
		.keo_fetch_timeout = NULL,
		.keo_fetch_changes = epoll_kev_copyin,
		.keo_put_events = NULL,
	};

	EV_SET(&kev, fd, filter, flags, 0, 0, 0);

        return kevent1(retval, epfd, &kev, 1, NULL, 0, NULL, &k_ops);
}

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
		return (1);

	return (0);
}

static int
epoll_delete_all_events(register_t *retval, int epfd, int fd)
{
	int error1, error2;

	error1 = epoll_register_kevent(retval, epfd, fd, EVFILT_READ, EV_DELETE);
	error2 = epoll_register_kevent(retval, epfd, fd, EVFILT_WRITE, EV_DELETE);

	/* return 0 if at least one result positive */
	return (error1 == 0 ? 0 : error2);
}
