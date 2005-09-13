/*	$NetBSD: tmpfs_vnops.h,v 1.3 2005/09/13 14:29:18 yamt Exp $	*/

/*
 * Copyright (c) 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(_TMPFS_VNOPS_H_)
#define _TMPFS_VNOPS_H_

#if !defined(_KERNEL)
#  error "This file is not meant to be included by userland."
#endif

#include <miscfs/genfs/genfs.h>

/* --------------------------------------------------------------------- */

/*
 * Declarations for tmpfs_vnops.c.
 */

extern int (**tmpfs_vnodeop_p)(void *);

int	tmpfs_lookup		(void *);
int	tmpfs_create		(void *);
int	tmpfs_mknod		(void *);
int	tmpfs_open		(void *);
int	tmpfs_close		(void *);
int	tmpfs_access		(void *);
int	tmpfs_getattr		(void *);
int	tmpfs_setattr		(void *);
int	tmpfs_read		(void *);
int	tmpfs_write		(void *);
#define	tmpfs_fcntl		genfs_fcntl
#define	tmpfs_ioctl		genfs_enoioctl
#define	tmpfs_poll		genfs_poll
#define	tmpfs_kqfilter		genfs_eopnotsupp
#define	tmpfs_revoke		genfs_revoke
#define	tmpfs_mmap		genfs_mmap
int	tmpfs_fsync		(void *);
#define	tmpfs_seek		genfs_seek
int	tmpfs_remove		(void *);
int	tmpfs_link		(void *);
int	tmpfs_rename		(void *);
int	tmpfs_mkdir		(void *);
int	tmpfs_rmdir		(void *);
int	tmpfs_symlink		(void *);
int	tmpfs_readdir		(void *);
int	tmpfs_readlink		(void *);
#define	tmpfs_abortop		genfs_abortop
int	tmpfs_inactive		(void *);
int	tmpfs_reclaim		(void *);
#define	tmpfs_lock		genfs_lock
#define	tmpfs_unlock		genfs_unlock
#define	tmpfs_bmap		genfs_eopnotsupp
#define	tmpfs_strategy		genfs_eopnotsupp
int	tmpfs_print		(void *);
int	tmpfs_pathconf		(void *);
#define	tmpfs_islocked		genfs_islocked
#define	tmpfs_advlock		genfs_eopnotsupp
#define	tmpfs_blkatoff		genfs_eopnotsupp
#define	tmpfs_valloc		genfs_eopnotsupp
#define	tmpfs_reallocblks	genfs_eopnotsupp
#define	tmpfs_vfree		genfs_eopnotsupp
int	tmpfs_truncate		(void *);
int	tmpfs_update		(void *);
#define	tmpfs_lease		genfs_lease_check
#define	tmpfs_bwrite		genfs_nullop
int	tmpfs_getpages		(void *);
int	tmpfs_putpages		(void *);

/* --------------------------------------------------------------------- */

#endif /* !defined(_TMPFS_VNOPS_H_) */
