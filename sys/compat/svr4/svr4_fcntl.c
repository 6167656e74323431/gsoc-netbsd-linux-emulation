/* $NetBSD: svr4_fcntl.c,v 1.1 1994/10/24 17:37:38 deraadt Exp $	*/
/*
 * Copyright (c) 1994 Christos Zoulas
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/filedesc.h>
#include <sys/ioctl.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/malloc.h>

#include <sys/syscallargs.h>

#include <compat/svr4/svr4_types.h>
#include <compat/svr4/svr4_syscallargs.h>
#include <compat/svr4/svr4_util.h>
#include <compat/svr4/svr4_fcntl.h>


static int
svr4_to_bsd_cmd(cmd)
    int cmd;
{
    switch (cmd) {
    case SVR4_F_DUPFD:
	return F_DUPFD;
    case SVR4_F_GETFD:
	return F_GETFD;
    case SVR4_F_SETFD:
	return F_SETFD;
    case SVR4_F_GETFL:
	return F_GETFL;
    case SVR4_F_SETFL:
	return F_SETFL;
    case SVR4_F_GETLK:
	return F_GETLK;
    case SVR4_F_SETLK:
	return F_SETLK;
    case SVR4_F_SETLKW:
	return F_SETLKW;
    default:
	return -1;
    }
}


static int
svr4_to_bsd_flags(l)
    int l;
{
    int r = 0;
    r |= (l & SVR4_O_RDONLY)   ? O_RDONLY   : 0;
    r |= (l & SVR4_O_WRONLY)   ? O_WRONLY   : 0;
    r |= (l & SVR4_O_RDWR)     ? O_RDWR     : 0;
    r |= (l & SVR4_O_NDELAY)   ? O_NONBLOCK : 0;
    r |= (l & SVR4_O_APPEND)   ? O_APPEND   : 0;
    r |= (l & SVR4_O_SYNC)     ? O_FSYNC    : 0;
    r |= (l & SVR4_O_RAIOSIG)  ? O_ASYNC    : 0;
    r |= (l & SVR4_O_NONBLOCK) ? O_NONBLOCK : 0;
    r |= (l & SVR4_O_PRIV)     ? O_EXLOCK   : 0;
    r |= (l & SVR4_O_CREAT)    ? O_CREAT    : 0;
    r |= (l & SVR4_O_TRUNC)    ? O_TRUNC    : 0;
    r |= (l & SVR4_O_EXCL)     ? O_EXCL     : 0;
    r |= (l & SVR4_O_NOCTTY)   ? O_NOCTTY   : 0;
    return r;
}


static int
bsd_to_svr4_flags(l)
    int l;
{
    int r = 0;
    r |= (l & O_RDONLY)   ? SVR4_O_RDONLY   : 0;
    r |= (l & O_WRONLY)   ? SVR4_O_WRONLY   : 0;
    r |= (l & O_RDWR)     ? SVR4_O_RDWR     : 0;
    r |= (l & O_NDELAY)   ? SVR4_O_NONBLOCK : 0;
    r |= (l & O_APPEND)   ? SVR4_O_APPEND   : 0;
    r |= (l & O_FSYNC)    ? SVR4_O_SYNC     : 0;
    r |= (l & O_ASYNC)    ? SVR4_O_RAIOSIG  : 0;
    r |= (l & O_NONBLOCK) ? SVR4_O_NONBLOCK : 0;
    r |= (l & O_EXLOCK)   ? SVR4_O_PRIV     : 0;
    r |= (l & O_CREAT)    ? SVR4_O_CREAT    : 0;
    r |= (l & O_TRUNC)    ? SVR4_O_TRUNC    : 0;
    r |= (l & O_EXCL)     ? SVR4_O_EXCL     : 0;
    r |= (l & O_NOCTTY)   ? SVR4_O_NOCTTY   : 0;
    return r;
}

static void
bsd_to_svr4_flock(iflp, oflp)
    struct flock *iflp;
    struct svr4_flock *oflp;
{
    switch (iflp->l_type) {
    case F_RDLCK:
	oflp->l_type = SVR4_F_RDLCK;
	break;
    case F_WRLCK:
	oflp->l_type = SVR4_F_WRLCK;
	break;
    case F_UNLCK:
	oflp->l_type = SVR4_F_UNLCK;
	break;
    default:
	oflp->l_type = -1;
	break;
    }

    oflp->l_whence = (short) iflp->l_whence;
    oflp->l_start  = (svr4_off_t) iflp->l_start;
    oflp->l_len    = (svr4_off_t) iflp->l_len;
    oflp->l_sysid  = 0;
    oflp->l_pid    = (svr4_pid_t) iflp->l_pid;
}


static void
svr4_to_bsd_flock(iflp, oflp)
    struct svr4_flock *iflp;
    struct flock *oflp;
{
    switch (iflp->l_type) {
    case SVR4_F_RDLCK:
	oflp->l_type = F_RDLCK;
	break;
    case SVR4_F_WRLCK:
	oflp->l_type = F_WRLCK;
	break;
    case SVR4_F_UNLCK:
	oflp->l_type = F_UNLCK;
	break;
    default:
	oflp->l_type = -1;
	break;
    }

    oflp->l_whence = iflp->l_whence;
    oflp->l_start = (off_t) iflp->l_start;
    oflp->l_len = (off_t) iflp->l_len;
    oflp->l_pid = (pid_t) iflp->l_pid;

}

int
svr4_open(p, uap, retval)
    register struct proc *p;
    register struct svr4_open_args *uap;
    register_t *retval;
{
    int error;
    struct open_args cup;
    

    stackgap_init();
    CHECKALT(p, SCARG(uap, path));

    SCARG(&cup, path) = SCARG(uap, path);
    SCARG(&cup, flags) = svr4_to_bsd_flags(SCARG(uap, flags));
    SCARG(&cup, mode) = SCARG(uap, mode);
    error = open(p, &cup, retval);

    if (error)
	return error;

    if ((SCARG(&cup, flags) & O_NOCTTY) && SESS_LEADER(p) &&
	!(p->p_flag & P_CONTROLT)) {
	struct filedesc *fdp = p->p_fd;
	struct file *fp = fdp->fd_ofiles[*retval];

	/* ignore any error, just give it a try */
	if (fp->f_type == DTYPE_VNODE)
	    (fp->f_ops->fo_ioctl)(fp, TIOCSCTTY, (caddr_t) 0, p);
    }

    return 0;
}


int
svr4_creat(p, uap, retval)
    register struct proc *p;
    register struct svr4_creat_args *uap;
    register_t *retval;
{
    struct open_args cup;

    stackgap_init();
    CHECKALT(p, SCARG(uap, path));

    SCARG(&cup, path) = SCARG(uap, path);
    SCARG(&cup, mode) = SCARG(uap, mode);
    SCARG(&cup, flags) = O_WRONLY | O_CREAT | O_TRUNC;

    return open(p, &cup, retval);
}


int
svr4_access(p, uap, retval)
    register struct proc *p;
    register struct svr4_access_args *uap;
    register_t *retval;
{
    struct access_args cup;

    stackgap_init();
    CHECKALT(p, SCARG(uap, path));
    SCARG(&cup, path) = SCARG(uap, path);
    SCARG(&cup, flags) = SCARG(uap, flags);

    return access(p, &cup, retval);
}


int
svr4_fcntl(p, uap, retval)
    register struct proc *p;
    register struct svr4_fcntl_args *uap;
    register_t *retval;
{
    int error;
    struct fcntl_args fa;

    SCARG(&fa, fd) = SCARG(uap, fd);
    SCARG(&fa, cmd) = svr4_to_bsd_cmd(SCARG(uap, cmd));

    switch(SCARG(&fa, cmd)) {
    case F_DUPFD:
    case F_GETFD:
    case F_SETFD:
	SCARG(&fa, arg) = SCARG(uap, arg);
	return fcntl(p, &fa, retval);

    case F_GETFL:
	SCARG(&fa, arg) = SCARG(uap, arg);
	error = fcntl(p, &fa, retval);
	if (error)
	    return error;
	*retval = bsd_to_svr4_flags(*retval);
	return error;

    case F_SETFL:
	SCARG(&fa, arg) = (void *) svr4_to_bsd_flags(SCARG(uap, arg));
	return fcntl(p, &fa, retval);

    case F_GETLK:
    case F_SETLK:
	{
	    struct svr4_flock ifl;
	    struct flock *flp, fl;

	    stackgap_init();

	    flp = stackgap_alloc(sizeof(struct flock));
	    SCARG(&fa, arg) = (void *) flp;

	    error = copyin(SCARG(uap, arg), &ifl, sizeof ifl);
	    if (error)
		return error;

	    svr4_to_bsd_flock(&ifl, &fl);

	    error = copyout(&fl, flp, sizeof fl);
	    if (error)
		return error;

	    error = fcntl(p, &fa, retval);
	    if (error || SCARG(&fa, cmd) != F_GETLK)
		return error;

	    error = copyin(flp, &fl, sizeof fl);
	    if (error)
		return error;

	    bsd_to_svr4_flock(&fl, &ifl);

	    return copyout(&ifl, SCARG(uap, arg), sizeof ifl);
	}
    default:
	return ENOSYS;
    }
}
