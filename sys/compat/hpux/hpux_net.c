/*	$NetBSD: hpux_net.c,v 1.8 1994/10/26 02:45:17 cgd Exp $	*/

/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 * from: Utah $Hdr: hpux_net.c 1.8 93/08/02$
 *
 *	@(#)hpux_net.c	8.2 (Berkeley) 9/9/93
 */

/*
 * Network related HP-UX compatibility routines
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/ktrace.h>

#include <hp300/hpux/hpux.h>

#define MINBSDIPCCODE	0x3EE
#define NUMBSDIPC	32

/*
 * HPUX netioctl() to BSD syscall map.
 * Indexed by callno - MINBSDIPCCODE
 */
extern int socket(), listen(), bind(), oaccept(), connect(), orecv();
extern int osend(), shutdown(), ogetsockname(), sendto();
extern int orecvfrom(), ogetpeername();
int hpux_getsockopt(), hpux_setsockopt();

struct hpuxtobsdipc {
	int (*rout)();
	int nargs;
} hpuxtobsdipc[NUMBSDIPC] = {
	socket,		3, /* 3ee */	listen,		2, /* 3ef */
	bind,		3, /* 3f0 */	oaccept,	3, /* 3f1 */
	connect,	3, /* 3f2 */	orecv,		4, /* 3f3 */
	osend,		4, /* 3f4 */	shutdown,	2, /* 3f5 */
	ogetsockname,	3, /* 3f6 */	hpux_setsockopt,5, /* 3f7 */
	sendto,		6, /* 3f8 */	orecvfrom,	6, /* 3f9 */
	ogetpeername,	3, /* 3fa */	NULL,		0, /* 3fb */
	NULL,		0, /* 3fc */	NULL,		0, /* 3fd */
	NULL,		0, /* 3fe */	NULL,		0, /* 3ff */
	NULL,		0, /* 400 */	NULL,		0, /* 401 */
	NULL,		0, /* 402 */	NULL,		0, /* 403 */
	NULL,		0, /* 404 */	NULL,		0, /* 405 */
	NULL,		0, /* 406 */	NULL,		0, /* 407 */
	NULL,		0, /* 408 */	NULL,		0, /* 409 */
	NULL,		0, /* 40a */	hpux_getsockopt,5, /* 40b */
	NULL,		0, /* 40c */	NULL,		0, /* 40d */
};

/*
 * Single system call entry to BSD style IPC.
 * Gleened from disassembled libbsdipc.a syscall entries.
 */
struct hpux_netioctl_args {
	int	call;
	int	*args;
};
hpux_netioctl(p, uap, retval)
	struct proc *p;
	struct hpux_netioctl_args *uap;
	register_t *retval;
{
	int *args, i;
	register int code;
	int error;

	args = SCARG(uap, args);
	code = SCARG(uap, call) - MINBSDIPCCODE;
	if (code < 0 || code >= NUMBSDIPC || hpuxtobsdipc[code].rout == NULL)
		return (EINVAL);
	if ((i = hpuxtobsdipc[code].nargs * sizeof (int)) &&
	    (error = copyin((caddr_t)args, (caddr_t)uap, (u_int)i))) {
#ifdef KTRACE
                if (KTRPOINT(p, KTR_SYSCALL))
                        ktrsyscall(p->p_tracep, code + MINBSDIPCCODE,
				   hpuxtobsdipc[code].nargs, (int *)uap);
#endif
		return (error);
	}
#ifdef KTRACE
        if (KTRPOINT(p, KTR_SYSCALL))
                ktrsyscall(p->p_tracep, code + MINBSDIPCCODE,
			   hpuxtobsdipc[code].nargs, (int *)uap);
#endif
	return ((*hpuxtobsdipc[code].rout)(p, uap, retval));
}

socksetsize(size, m)
	int size;
	struct mbuf *m;
{
	register int tmp;

	if (size < sizeof(int)) {
		switch(size) {
	    	case 1:
			tmp = (int) *mtod(m, char *);
			break;
	    	case 2:
			tmp = (int) *mtod(m, short *);
			break;
	    	case 3:
			tmp = (((int) *mtod(m, int *)) >> 8) & 0xffffff;
			break;
		}
		*mtod(m, int *) = tmp;
		m->m_len = sizeof(int);
	} else {
		m->m_len = size;
	}
}

struct hpux_setsockopt_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	valsize;
};
/* ARGSUSED */
hpux_setsockopt(p, uap, retval)
	struct proc *p;
	struct hpux_setsockopt_args *uap;
	register_t *retval;
{
	struct file *fp;
	struct mbuf *m = NULL;
	int tmp, error;

	if (error = getsock(p->p_fd, SCARG(uap, s), &fp))
		return (error);
	if (SCARG(uap, valsize) > MLEN)
		return (EINVAL);
	if (SCARG(uap, val)) {
		m = m_get(M_WAIT, MT_SOOPTS);
		if (m == NULL)
			return (ENOBUFS);
		if (error = copyin(SCARG(uap, val), mtod(m, caddr_t),
		    (u_int)SCARG(uap, valsize))) {
			(void) m_free(m);
			return (error);
		}
		if (SCARG(uap, name) == SO_LINGER) {
			tmp = *mtod(m, int *);
			mtod(m, struct linger *)->l_onoff = 1;
			mtod(m, struct linger *)->l_linger = tmp;
			m->m_len = sizeof(struct linger);
		} else
			socksetsize(SCARG(uap, valsize), m);
	} else if (SCARG(uap, name) == ~SO_LINGER) {
		m = m_get(M_WAIT, MT_SOOPTS);
		if (m) {
			SCARG(uap, name) = SO_LINGER;
			mtod(m, struct linger *)->l_onoff = 0;
			m->m_len = sizeof(struct linger);
		}
	}
	return (sosetopt((struct socket *)fp->f_data, SCARG(uap, level),
	    SCARG(uap, name), m));
}

struct hpux_setsockopt2_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	valsize;
};
/* ARGSUSED */
hpux_setsockopt2(p, uap, retval)
	struct proc *p;
	register struct hpux_setsockopt2_args *uap;
	register_t *retval;
{
	struct file *fp;
	struct mbuf *m = NULL;
	int error;

	if (error = getsock(p->p_fd, SCARG(uap, s), &fp))
		return (error);
	if (SCARG(uap, valsize) > MLEN)
		return (EINVAL);
	if (SCARG(uap, val)) {
		m = m_get(M_WAIT, MT_SOOPTS);
		if (m == NULL)
			return (ENOBUFS);
		if (error = copyin(SCARG(uap, val), mtod(m, caddr_t),
		    (u_int)SCARG(uap, valsize))) {
			(void) m_free(m);
			return (error);
		}
		socksetsize(SCARG(uap, valsize), m);
	}
	return (sosetopt((struct socket *)fp->f_data, SCARG(uap, level),
	    SCARG(uap, name), m));
}

struct hpux_getsockopt_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	*avalsize;
};
hpux_getsockopt(p, uap, retval)
	struct proc *p;
	struct hpux_getsockopt_args *uap;
	register_t *retval;
{
	struct file *fp;
	struct mbuf *m = NULL;
	int valsize, error;

	if (error = getsock(p->p_fd, SCARG(uap, s), &fp))
		return (error);
	if (SCARG(uap, val)) {
		if (error = copyin((caddr_t)SCARG(uap, avalsize),
		    (caddr_t)&valsize, sizeof (valsize)))
			return (error);
	} else
		valsize = 0;
	if (error = sogetopt((struct socket *)fp->f_data, SCARG(uap, level),
	    SCARG(uap, name), &m))
		goto bad;
	if (SCARG(uap, val) && valsize && m != NULL) {
		if (SCARG(uap, name) == SO_LINGER) {
			if (mtod(m, struct linger *)->l_onoff)
				*mtod(m, int *) = mtod(m, struct linger *)->l_linger;
			else
				*mtod(m, int *) = 0;
			m->m_len = sizeof(int);
		}
		if (valsize > m->m_len)
			valsize = m->m_len;
		error = copyout(mtod(m, caddr_t), SCARG(uap, val),
		    (u_int)valsize);
		if (error == 0)
			error = copyout((caddr_t)&valsize,
			    (caddr_t)SCARG(uap, avalsize), sizeof (valsize));
	}
bad:
	if (m != NULL)
		(void) m_free(m);
	return (error);
}
