/*	$NetBSD: pud_dev.c,v 1.2 2007/11/21 11:19:44 pooka Exp $	*/

/*
 * Copyright (c) 2007  Antti Kantee.  All Rights Reserved.
 *
 * Development of this software was supported by the
 * Research Foundation of Helsinki University of Technology
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: pud_dev.c,v 1.2 2007/11/21 11:19:44 pooka Exp $");

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/socketvar.h>

#include <dev/pud/pud_sys.h>

/*
 * Block de-vices
 */

static dev_type_open(pud_bdev_open);
static dev_type_close(pud_bdev_close);
static dev_type_strategy(pud_bdev_strategy);
static dev_type_ioctl(pud_bdev_ioctl);
#if 0
static dev_type_dump(pud_bdev_dump);
static dev_type_size(pud_bdev_size);
#endif

struct bdevsw pud_bdevsw = {
	.d_open		= pud_bdev_open,
	.d_close	= pud_bdev_close,
	.d_strategy	= pud_bdev_strategy,
	.d_ioctl	= pud_bdev_ioctl,
#if 0
	.d_dump		= pud_bdev_dump,
	.d_psize	= pud_bdev_size,
#endif
};

static int
pud_bdev_open(dev_t dev, int flags, int fmt, lwp_t *l)
{

	return EOPNOTSUPP;
}

static int
pud_bdev_close(dev_t dev, int flags, int fmt, lwp_t *l)
{

	return EOPNOTSUPP;
}

static void
pud_bdev_strategy(struct buf *bp)
{

	bp->b_error = EOPNOTSUPP;
	biodone(bp);
}

int
pud_bdev_ioctl(dev_t dev, u_long cmd, void *data, int dlen, lwp_t *l)
{

	return EOPNOTSUPP;
}

/* hnmmm */
#if 0
int
pud_bdev_dump(dev_t dev, daddr_t addr, void *data, size_t sz)
{

	return EOPNOTSUPP;
}

int
pud_bdev_size(dev_t dev)
{

	return 0;
}
#endif

/*
 * Charrr devices
 */

static dev_type_open(pud_cdev_open);
static dev_type_close(pud_cdev_close);
static dev_type_read(pud_cdev_read);
static dev_type_write(pud_cdev_write);
static dev_type_ioctl(pud_cdev_ioctl);
static dev_type_poll(pud_cdev_poll);
static dev_type_mmap(pud_cdev_mmap);
static dev_type_kqfilter(pud_cdev_kqfilter);

struct cdevsw pud_cdevsw = {
	.d_open		= pud_cdev_open,
	.d_close	= pud_cdev_close,
	.d_read		= pud_cdev_read,
	.d_write	= pud_cdev_write,
	.d_ioctl	= pud_cdev_ioctl,
#if 0
	.d_stop		= pud_cdev_stop,
	.d_tty		= pud_cdev_tty,
#endif
	.d_poll		= pud_cdev_poll,
	.d_mmap		= pud_cdev_mmap,
	.d_kqfilter	= pud_cdev_kqfilter,
	.d_flag		= D_OTHER,
};

static int
pud_cdev_open(dev_t dev, int flags, int fmt, lwp_t *l)
{
	struct pud_creq_open pc_open; /* XXX: stack = stupid */

	pc_open.pm_flags = flags;
	pc_open.pm_fmt = fmt;

	return pud_request(dev, &pc_open, sizeof(pc_open),
	    PUD_REQ_CDEV, PUD_CDEV_OPEN);
}

static int
pud_cdev_close(dev_t dev, int flags, int fmt, lwp_t *l)
{
	struct pud_creq_close pc_close; /* XXX: stack = stupid */

	pc_close.pm_flags = flags;
	pc_close.pm_fmt = fmt;

	return pud_request(dev, &pc_close, sizeof(pc_close),
	    PUD_REQ_CDEV, PUD_CDEV_CLOSE);
}

static int
pud_cdev_read(dev_t dev, struct uio *uio, int flag)
{
	struct pud_creq_read *pc_read;
	size_t allocsize;
	int error;

	allocsize = sizeof(struct pud_creq_read) + uio->uio_resid;
	pc_read = kmem_zalloc(allocsize, KM_SLEEP);

	pc_read->pm_offset = uio->uio_offset;
	pc_read->pm_resid = uio->uio_resid;

	error = pud_request(dev, pc_read, allocsize,
	    PUD_REQ_CDEV, PUD_CDEV_READ);
	if (error)
		goto out;

	if (pc_read->pm_resid > uio->uio_resid) {
		error = EINVAL;
		goto out;
	}

	error = uiomove(pc_read->pm_data, pc_read->pm_resid, uio);

 out:
	kmem_free(pc_read, allocsize);
	return error;
}

static int
pud_cdev_write(dev_t dev, struct uio *uio, int flag)
{
	struct pud_creq_write *pc_write;
	size_t allocsize;
	int error;

	allocsize = sizeof(struct pud_creq_write) + uio->uio_resid;
	pc_write = kmem_zalloc(allocsize, KM_SLEEP);

	pc_write->pm_offset = uio->uio_offset;
	pc_write->pm_resid = uio->uio_resid;

	error = uiomove(pc_write->pm_data, uio->uio_resid, uio);
	if (error)
		goto out;

	error = pud_request(dev, pc_write, allocsize,
	    PUD_REQ_CDEV, PUD_CDEV_WRITE);
	if (error)
		goto out;

	if (pc_write->pm_resid)
		error = EIO;

 out:
	kmem_free(pc_write, allocsize);
	return error;
}

static int
pud_cdev_ioctl(dev_t dev, u_long cmd, void *data, int flag, lwp_t *l)
{

	return EOPNOTSUPP;
}

static paddr_t
pud_cdev_mmap(dev_t dev, off_t off, int flag)
{

	return (paddr_t)-1;
}

static int
pud_cdev_poll(dev_t dev, int flag, lwp_t *l)
{

	return EOPNOTSUPP;
}

static int
pud_cdev_kqfilter(dev_t dev, struct knote *kn)
{

	return EOPNOTSUPP;
}
