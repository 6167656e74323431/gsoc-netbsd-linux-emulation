/*	$NetBSD: tty_pty.c,v 1.49 2000/09/11 13:51:29 pk Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)tty_pty.c	8.4 (Berkeley) 2/20/95
 */

/*
 * Pseudo-teletype Driver
 * (Actually two drivers, requiring two entries in 'cdevsw')
 */

#include "opt_compat_sunos.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/signalvar.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/poll.h>
#include <sys/malloc.h>

#define	DEFAULT_NPTYS		16	/* default number of initial ptys */
#define DEFAULT_MAXPTYS		256	/* default maximum number of ptys */

/* Macros to clear/set/test flags. */
#define	SET(t, f)	(t) |= (f)
#define	CLR(t, f)	(t) &= ~((unsigned)(f))
#define	ISSET(t, f)	((t) & (f))

#define BUFSIZ 100		/* Chunk size iomoved to/from user */

/*
 * pts == /dev/tty[pqrs]?
 * ptc == /dev/pty[pqrs]?
 */
struct	pt_softc {
	struct	tty *pt_tty;
	int	pt_flags;
	struct	selinfo pt_selr, pt_selw;
	u_char	pt_send;
	u_char	pt_ucntl;
};

static struct pt_softc **pt_softc = NULL;	/* pty array */
static int npty = 0;			/* for pstat -t */
static int maxptys = DEFAULT_MAXPTYS;	/* maximum number of ptys (sysctable) */

#if defined(MULTIPROCESSOR) || defined(LOCKDEBUG)
static struct simplelock pt_softc_mutex = SIMPLELOCK_INITIALIZER;
#endif

#define	PF_PKT		0x08		/* packet mode */
#define	PF_STOPPED	0x10		/* user told stopped */
#define	PF_REMOTE	0x20		/* remote and flow controlled input */
#define	PF_NOSTOP	0x40
#define PF_UCNTL	0x80		/* user control mode */

void	ptyattach __P((int));
void	ptcwakeup __P((struct tty *, int));
int	ptcopen __P((dev_t, int, int, struct proc *));
struct tty *ptytty __P((dev_t));
void	ptsstart __P((struct tty *));
int	pty_maxptys __P((int, int));

static struct pt_softc **ptyarralloc __P((int));
static int check_pty __P((dev_t));

/*
 * Allocate and zero array of nelem elements.
 */
static struct pt_softc **
ptyarralloc(nelem)
	int nelem;
{
	struct pt_softc **pt;
	nelem += 10;
	pt = malloc(nelem * sizeof(struct pt_softc *), M_DEVBUF, M_WAITOK);
	memset(pt, '\0', nelem * sizeof(struct pt_softc *));
	return pt;
}

/*
 * Check if the minor is correct and ensure necessary structures
 * are properly allocated.
 */
static int
check_pty(dev)
	dev_t dev;
{
	struct pt_softc *pti;

	if (minor(dev) >= npty) {
		struct pt_softc **newpt;
		int newnpty;

		/* check if the requested pty can be granted */
		if (minor(dev) >= maxptys) {
	    limit_reached:
			tablefull("pty", "increase kern.maxptys");
			simple_unlock(&pt_softc_mutex);
			return (ENXIO);
		}

		/*
		 * Now grab the pty array mutex - we need to ensure
		 * that the pty array is consistent while copying it's
		 * content to newly allocated, larger space; we also
		 * need to be safe against pty_maxptys().
		 */
		simple_lock(&pt_softc_mutex);

		do {
			for(newnpty = npty; newnpty <= minor(dev);
				newnpty *= 2);

			if (newnpty > maxptys)
				newnpty = maxptys;

			simple_unlock(&pt_softc_mutex);
			newpt = ptyarralloc(newnpty);
			simple_lock(&pt_softc_mutex);

			if (maxptys == npty) {
				/* we hold the mutex here */
				goto limit_reached;
			}
		} while(newnpty > maxptys);

		/*
		 * If the pty array was not enlarged while we were waiting
		 * for mutex, copy current contents of pt_softc[] to newly
		 * allocated array and start using the new bigger array.
		 */
		if (minor(dev) >= npty) {
			memcpy(newpt, pt_softc, npty*sizeof(struct pt_softc *));
			free(pt_softc, M_DEVBUF);

			pt_softc = newpt;
			npty = newnpty;
		} else {
			/* was enlarged when waited fot lock, free new space */
			free(newpt, M_DEVBUF);
		}

		simple_unlock(&pt_softc_mutex);
	}
		
	/*
	 * If the entry is not yet allocated, allocate one. The mutex is
	 * needed so that the state of pt_softc[] array is consistant
	 * in case it has been longened above.
	 */
	if (!pt_softc[minor(dev)]) {
		MALLOC(pti, struct pt_softc *, sizeof(struct pt_softc),
			M_DEVBUF, M_WAITOK);

	 	pti->pt_tty = ttymalloc();

		simple_lock(&pt_softc_mutex);

		/*
		 * Check the entry again - it might have been
		 * added while we were waiting for mutex.
		 */
		if (!pt_softc[minor(dev)]) {
			tty_attach(pti->pt_tty);
			pt_softc[minor(dev)] = pti;
		} else {
			ttyfree(pti->pt_tty);
			FREE(pti, M_DEVBUF);
		}

		simple_unlock(&pt_softc_mutex);
	}

	return (0);
}

/*
 * Set maxpty in thread-safe way. Returns 0 in case of error, otherwise
 * new value of maxptys.
 */
int
pty_maxptys(newmax, set)
	int newmax, set;
{
	if (!set)
		return (maxptys);

	/* the value cannot be set to value lower than current number of ptys */
	if (newmax < npty)
		return (0);

	/* can proceed immediatelly if bigger than current maximum */
	if (newmax > maxptys) {
		maxptys = newmax;
		return (maxptys);
	}

	/*
	 * We have to grab the pt_softc lock, so that we would pick correct
	 * value of npty (might be modified in check_pty()).
	 */
	simple_lock(&pt_softc_mutex);

	if (newmax > npty)
		maxptys = newmax;

	simple_unlock(&pt_softc_mutex);

	return (maxptys);
}

/*
 * Establish n (or default if n is 1) ptys in the system.
 */
void
ptyattach(n)
	int n;
{
	/* maybe should allow 0 => none? */
	if (n <= 1)
		n = DEFAULT_NPTYS;
	pt_softc = ptyarralloc(n);
	npty = n;
}

/*ARGSUSED*/
int
ptsopen(dev, flag, devtype, p)
	dev_t dev;
	int flag, devtype;
	struct proc *p;
{
	struct pt_softc *pti;
	struct tty *tp;
	int error;

	if ((error = check_pty(dev)))
		return (error);

	pti = pt_softc[minor(dev)];
	tp = pti->pt_tty;

	if (!ISSET(tp->t_state, TS_ISOPEN)) {
		ttychars(tp);		/* Set up default chars */
		tp->t_iflag = TTYDEF_IFLAG;
		tp->t_oflag = TTYDEF_OFLAG;
		tp->t_lflag = TTYDEF_LFLAG;
		tp->t_cflag = TTYDEF_CFLAG;
		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
		ttsetwater(tp);		/* would be done in xxparam() */
	} else if (ISSET(tp->t_state, TS_XCLUDE) && p->p_ucred->cr_uid != 0)
		return (EBUSY);
	if (tp->t_oproc)			/* Ctrlr still around. */
		SET(tp->t_state, TS_CARR_ON);
	if (!ISSET(flag, O_NONBLOCK))
		while (!ISSET(tp->t_state, TS_CARR_ON)) {
			tp->t_wopen++;
			error = ttysleep(tp, &tp->t_rawq, TTIPRI | PCATCH,
			    ttopen, 0);
			tp->t_wopen--;
			if (error)
				return (error);
		}
	error = (*linesw[tp->t_line].l_open)(dev, tp);
	ptcwakeup(tp, FREAD|FWRITE);
	return (error);
}

int
ptsclose(dev, flag, mode, p)
	dev_t dev;
	int flag, mode;
	struct proc *p;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;
	int error;

	error = (*linesw[tp->t_line].l_close)(tp, flag);
	error |= ttyclose(tp);
	ptcwakeup(tp, FREAD|FWRITE);
	return (error);
}

int
ptsread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	struct proc *p = curproc;
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;
	int error = 0;

again:
	if (pti->pt_flags & PF_REMOTE) {
		while (isbackground(p, tp)) {
			if (sigismember(&p->p_sigignore, SIGTTIN) ||
			    sigismember(&p->p_sigmask, SIGTTIN) ||
			    p->p_pgrp->pg_jobc == 0 ||
			    p->p_flag & P_PPWAIT)
				return (EIO);
			pgsignal(p->p_pgrp, SIGTTIN, 1);
			error = ttysleep(tp, (caddr_t)&lbolt,
					 TTIPRI | PCATCH, ttybg, 0);
			if (error)
				return (error);
		}
		if (tp->t_canq.c_cc == 0) {
			if (flag & IO_NDELAY)
				return (EWOULDBLOCK);
			error = ttysleep(tp, (caddr_t)&tp->t_canq,
					 TTIPRI | PCATCH, ttyin, 0);
			if (error)
				return (error);
			goto again;
		}
		while (tp->t_canq.c_cc > 1 && uio->uio_resid > 0)
			if (ureadc(getc(&tp->t_canq), uio) < 0) {
				error = EFAULT;
				break;
			}
		if (tp->t_canq.c_cc == 1)
			(void) getc(&tp->t_canq);
		if (tp->t_canq.c_cc)
			return (error);
	} else
		if (tp->t_oproc)
			error = (*linesw[tp->t_line].l_read)(tp, uio, flag);
	ptcwakeup(tp, FWRITE);
	return (error);
}

/*
 * Write to pseudo-tty.
 * Wakeups of controlling tty will happen
 * indirectly, when tty driver calls ptsstart.
 */
int
ptswrite(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;

	if (tp->t_oproc == 0)
		return (EIO);
	return ((*linesw[tp->t_line].l_write)(tp, uio, flag));
}

/*
 * Start output on pseudo-tty.
 * Wake up process polling or sleeping for input from controlling tty.
 */
void
ptsstart(tp)
	struct tty *tp;
{
	struct pt_softc *pti = pt_softc[minor(tp->t_dev)];

	if (ISSET(tp->t_state, TS_TTSTOP))
		return;
	if (pti->pt_flags & PF_STOPPED) {
		pti->pt_flags &= ~PF_STOPPED;
		pti->pt_send = TIOCPKT_START;
	}
	ptcwakeup(tp, FREAD);
}

void
ptsstop(tp, flush)
	struct tty *tp;
	int flush;
{
	struct pt_softc *pti = pt_softc[minor(tp->t_dev)];
	int flag;

	/* note: FLUSHREAD and FLUSHWRITE already ok */
	if (flush == 0) {
		flush = TIOCPKT_STOP;
		pti->pt_flags |= PF_STOPPED;
	} else
		pti->pt_flags &= ~PF_STOPPED;
	pti->pt_send |= flush;
	/* change of perspective */
	flag = 0;
	if (flush & FREAD)
		flag |= FWRITE;
	if (flush & FWRITE)
		flag |= FREAD;
	ptcwakeup(tp, flag);
}

void
ptcwakeup(tp, flag)
	struct tty *tp;
	int flag;
{
	struct pt_softc *pti = pt_softc[minor(tp->t_dev)];

	if (flag & FREAD) {
		selwakeup(&pti->pt_selr);
		wakeup((caddr_t)&tp->t_outq.c_cf);
	}
	if (flag & FWRITE) {
		selwakeup(&pti->pt_selw);
		wakeup((caddr_t)&tp->t_rawq.c_cf);
	}
}

/*ARGSUSED*/
int
ptcopen(dev, flag, devtype, p)
	dev_t dev;
	int flag, devtype;
	struct proc *p;
{
	struct pt_softc *pti;
	struct tty *tp;
	int error;

	if ((error = check_pty(dev)))
		return (error);

	pti = pt_softc[minor(dev)];
	tp = pti->pt_tty;

	if (tp->t_oproc)
		return (EIO);
	tp->t_oproc = ptsstart;
	(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	CLR(tp->t_lflag, EXTPROC);
	pti->pt_flags = 0;
	pti->pt_send = 0;
	pti->pt_ucntl = 0;
	return (0);
}

/*ARGSUSED*/
int
ptcclose(dev, flag, devtype, p)
	dev_t dev;
	int flag, devtype;
	struct proc *p;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;

	(void)(*linesw[tp->t_line].l_modem)(tp, 0);
	CLR(tp->t_state, TS_CARR_ON);
	tp->t_oproc = 0;		/* mark closed */
	return (0);
}

int
ptcread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;
	char buf[BUFSIZ];
	int error = 0, cc;

	/*
	 * We want to block until the slave
	 * is open, and there's something to read;
	 * but if we lost the slave or we're NBIO,
	 * then return the appropriate error instead.
	 */
	for (;;) {
		if (ISSET(tp->t_state, TS_ISOPEN)) {
			if (pti->pt_flags&PF_PKT && pti->pt_send) {
				error = ureadc((int)pti->pt_send, uio);
				if (error)
					return (error);
				if (pti->pt_send & TIOCPKT_IOCTL) {
					cc = min(uio->uio_resid,
						sizeof(tp->t_termios));
					uiomove((caddr_t) &tp->t_termios,
						cc, uio);
				}
				pti->pt_send = 0;
				return (0);
			}
			if (pti->pt_flags&PF_UCNTL && pti->pt_ucntl) {
				error = ureadc((int)pti->pt_ucntl, uio);
				if (error)
					return (error);
				pti->pt_ucntl = 0;
				return (0);
			}
			if (tp->t_outq.c_cc && !ISSET(tp->t_state, TS_TTSTOP))
				break;
		}
		if (!ISSET(tp->t_state, TS_CARR_ON))
			return (0);	/* EOF */
		if (flag & IO_NDELAY)
			return (EWOULDBLOCK);
		error = tsleep((caddr_t)&tp->t_outq.c_cf, TTIPRI | PCATCH,
			       ttyin, 0);
		if (error)
			return (error);
	}
	if (pti->pt_flags & (PF_PKT|PF_UCNTL))
		error = ureadc(0, uio);
	while (uio->uio_resid > 0 && error == 0) {
		cc = q_to_b(&tp->t_outq, buf, min(uio->uio_resid, BUFSIZ));
		if (cc <= 0)
			break;
		error = uiomove(buf, cc, uio);
	}
	if (tp->t_outq.c_cc <= tp->t_lowat) {
		if (ISSET(tp->t_state, TS_ASLEEP)) {
			CLR(tp->t_state, TS_ASLEEP);
			wakeup((caddr_t)&tp->t_outq);
		}
		selwakeup(&tp->t_wsel);
	}
	return (error);
}


int
ptcwrite(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;
	u_char *cp = NULL;
	int cc = 0;
	u_char locbuf[BUFSIZ];
	int cnt = 0;
	int error = 0;

again:
	if (!ISSET(tp->t_state, TS_ISOPEN))
		goto block;
	if (pti->pt_flags & PF_REMOTE) {
		if (tp->t_canq.c_cc)
			goto block;
		while (uio->uio_resid > 0 && tp->t_canq.c_cc < TTYHOG - 1) {
			if (cc == 0) {
				cc = min(uio->uio_resid, BUFSIZ);
				cc = min(cc, TTYHOG - 1 - tp->t_canq.c_cc);
				cp = locbuf;
				error = uiomove((caddr_t)cp, cc, uio);
				if (error)
					return (error);
				/* check again for safety */
				if (!ISSET(tp->t_state, TS_ISOPEN))
					return (EIO);
			}
			if (cc)
				(void) b_to_q((char *)cp, cc, &tp->t_canq);
			cc = 0;
		}
		(void) putc(0, &tp->t_canq);
		ttwakeup(tp);
		wakeup((caddr_t)&tp->t_canq);
		return (0);
	}
	while (uio->uio_resid > 0) {
		if (cc == 0) {
			cc = min(uio->uio_resid, BUFSIZ);
			cp = locbuf;
			error = uiomove((caddr_t)cp, cc, uio);
			if (error)
				return (error);
			/* check again for safety */
			if (!ISSET(tp->t_state, TS_ISOPEN))
				return (EIO);
		}
		while (cc > 0) {
			if ((tp->t_rawq.c_cc + tp->t_canq.c_cc) >= TTYHOG - 2 &&
			   (tp->t_canq.c_cc > 0 || !ISSET(tp->t_iflag, ICANON))) {
				wakeup((caddr_t)&tp->t_rawq);
				goto block;
			}
			(*linesw[tp->t_line].l_rint)(*cp++, tp);
			cnt++;
			cc--;
		}
		cc = 0;
	}
	return (0);
block:
	/*
	 * Come here to wait for slave to open, for space
	 * in outq, or space in rawq.
	 */
	if (!ISSET(tp->t_state, TS_CARR_ON))
		return (EIO);
	if (flag & IO_NDELAY) {
		/* adjust for data copied in but not written */
		uio->uio_resid += cc;
		if (cnt == 0)
			return (EWOULDBLOCK);
		return (0);
	}
	error = tsleep((caddr_t)&tp->t_rawq.c_cf, TTOPRI | PCATCH,
		       ttyout, 0);
	if (error) {
		/* adjust for data copied in but not written */
		uio->uio_resid += cc;
		return (error);
	}
	goto again;
}

int
ptcpoll(dev, events, p)
	dev_t dev;
	int events;
	struct proc *p;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;
	int revents = 0;
	int s = splsoftclock();

	if (events & (POLLIN | POLLRDNORM))
		if (ISSET(tp->t_state, TS_ISOPEN) &&
		    ((tp->t_outq.c_cc > 0 && !ISSET(tp->t_state, TS_TTSTOP)) ||
		     ((pti->pt_flags & PF_PKT) && pti->pt_send) ||
		     ((pti->pt_flags & PF_UCNTL) && pti->pt_ucntl)))
			revents |= events & (POLLIN | POLLRDNORM);

	if (events & (POLLOUT | POLLWRNORM))
		if (ISSET(tp->t_state, TS_ISOPEN) &&
		    ((pti->pt_flags & PF_REMOTE) ?
		     (tp->t_canq.c_cc == 0) :
		     ((tp->t_rawq.c_cc + tp->t_canq.c_cc < TTYHOG-2) ||
		      (tp->t_canq.c_cc == 0 && ISSET(tp->t_iflag, ICANON)))))
			revents |= events & (POLLOUT | POLLWRNORM);

	if (events & POLLHUP)
		if (!ISSET(tp->t_state, TS_CARR_ON))
			revents |= POLLHUP;

	if (revents == 0) {
		if (events & (POLLIN | POLLHUP | POLLRDNORM))
			selrecord(p, &pti->pt_selr);

		if (events & (POLLOUT | POLLWRNORM))
			selrecord(p, &pti->pt_selw);
	}

	splx(s);
	return (revents);
}


struct tty *
ptytty(dev)
	dev_t dev;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;

	return (tp);
}

/*ARGSUSED*/
int
ptyioctl(dev, cmd, data, flag, p)
	dev_t dev;
	u_long cmd;
	caddr_t data;
	int flag;
	struct proc *p;
{
	struct pt_softc *pti = pt_softc[minor(dev)];
	struct tty *tp = pti->pt_tty;
	u_char *cc = tp->t_cc;
	int stop, error, sig;

	/*
	 * IF CONTROLLER STTY THEN MUST FLUSH TO PREVENT A HANG.
	 * ttywflush(tp) will hang if there are characters in the outq.
	 */
	if (cmd == TIOCEXT) {
		/*
		 * When the EXTPROC bit is being toggled, we need
		 * to send an TIOCPKT_IOCTL if the packet driver
		 * is turned on.
		 */
		if (*(int *)data) {
			if (pti->pt_flags & PF_PKT) {
				pti->pt_send |= TIOCPKT_IOCTL;
				ptcwakeup(tp, FREAD);
			}
			SET(tp->t_lflag, EXTPROC);
		} else {
			if (ISSET(tp->t_lflag, EXTPROC) &&
			    (pti->pt_flags & PF_PKT)) {
				pti->pt_send |= TIOCPKT_IOCTL;
				ptcwakeup(tp, FREAD);
			}
			CLR(tp->t_lflag, EXTPROC);
		}
		return(0);
	} else
	if (cdevsw[major(dev)].d_open == ptcopen)
		switch (cmd) {

		case TIOCGPGRP:
#ifdef COMPAT_SUNOS
			{
			/*
			 * I'm not sure about SunOS TIOCGPGRP semantics
			 * on PTYs, but it's something like this:
			 */
			extern struct emul emul_sunos;
			if (p->p_emul == &emul_sunos && tp->t_pgrp == 0)
				return (EIO);
			*(int *)data = tp->t_pgrp->pg_id;
			return (0);
			}
#endif
			/*
			 * We avoid calling ttioctl on the controller since,
			 * in that case, tp must be the controlling terminal.
			 */
			*(int *)data = tp->t_pgrp ? tp->t_pgrp->pg_id : 0;
			return (0);

		case TIOCPKT:
			if (*(int *)data) {
				if (pti->pt_flags & PF_UCNTL)
					return (EINVAL);
				pti->pt_flags |= PF_PKT;
			} else
				pti->pt_flags &= ~PF_PKT;
			return (0);

		case TIOCUCNTL:
			if (*(int *)data) {
				if (pti->pt_flags & PF_PKT)
					return (EINVAL);
				pti->pt_flags |= PF_UCNTL;
			} else
				pti->pt_flags &= ~PF_UCNTL;
			return (0);

		case TIOCREMOTE:
			if (*(int *)data)
				pti->pt_flags |= PF_REMOTE;
			else
				pti->pt_flags &= ~PF_REMOTE;
			ttyflush(tp, FREAD|FWRITE);
			return (0);

#ifdef COMPAT_OLDTTY
		case TIOCSETP:
		case TIOCSETN:
#endif
		case TIOCSETD:
		case TIOCSETA:
		case TIOCSETAW:
		case TIOCSETAF:
			ndflush(&tp->t_outq, tp->t_outq.c_cc);
			break;

		case TIOCSIG:
			sig = (int)(long)*(caddr_t *)data;
			if (sig <= 0 || sig >= NSIG)
				return (EINVAL);
			if (!ISSET(tp->t_lflag, NOFLSH))
				ttyflush(tp, FREAD|FWRITE);
			pgsignal(tp->t_pgrp, sig, 1);
			if ((sig == SIGINFO) &&
			    (!ISSET(tp->t_lflag, NOKERNINFO)))
				ttyinfo(tp);
			return(0);
		}
	error = (*linesw[tp->t_line].l_ioctl)(tp, cmd, data, flag, p);
	if (error < 0)
		 error = ttioctl(tp, cmd, data, flag, p);
	if (error < 0) {
		if (pti->pt_flags & PF_UCNTL &&
		    (cmd & ~0xff) == UIOCCMD(0)) {
			if (cmd & 0xff) {
				pti->pt_ucntl = (u_char)cmd;
				ptcwakeup(tp, FREAD);
			}
			return (0);
		}
		error = ENOTTY;
	}
	/*
	 * If external processing and packet mode send ioctl packet.
	 */
	if (ISSET(tp->t_lflag, EXTPROC) && (pti->pt_flags & PF_PKT)) {
		switch(cmd) {
		case TIOCSETA:
		case TIOCSETAW:
		case TIOCSETAF:
#ifdef COMPAT_OLDTTY
		case TIOCSETP:
		case TIOCSETN:
		case TIOCSETC:
		case TIOCSLTC:
		case TIOCLBIS:
		case TIOCLBIC:
		case TIOCLSET:
#endif
			pti->pt_send |= TIOCPKT_IOCTL;
			ptcwakeup(tp, FREAD);
		default:
			break;
		}
	}
	stop = ISSET(tp->t_iflag, IXON) && CCEQ(cc[VSTOP], CTRL('s'))
		&& CCEQ(cc[VSTART], CTRL('q'));
	if (pti->pt_flags & PF_NOSTOP) {
		if (stop) {
			pti->pt_send &= ~TIOCPKT_NOSTOP;
			pti->pt_send |= TIOCPKT_DOSTOP;
			pti->pt_flags &= ~PF_NOSTOP;
			ptcwakeup(tp, FREAD);
		}
	} else {
		if (!stop) {
			pti->pt_send &= ~TIOCPKT_DOSTOP;
			pti->pt_send |= TIOCPKT_NOSTOP;
			pti->pt_flags |= PF_NOSTOP;
			ptcwakeup(tp, FREAD);
		}
	}
	return (error);
}
