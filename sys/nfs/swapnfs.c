/*
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	from: @(#)nfsswapvmunix.c	7.1 (Berkeley) 3/4/91
 *	$Id: swapnfs.c,v 1.1 1993/07/07 12:06:40 cgd Exp $
 */

/*
 * Sample NFS swapvmunix configuration file.
 * This should be filled in by the bootstrap program.
 * See /sys/nfs/nfsdiskless.h for details of the fields.
 */

#include "../sys/param.h"
#include "../sys/conf.h"
#include "../sys/socket.h"
#include "../sys/mount.h"
#include "../net/if.h"
#include "../nfs/nfsv2.h"
#include "../nfs/nfsdiskless.h"

dev_t	rootdev = NODEV;
dev_t	argdev  = NODEV;
dev_t	dumpdev = NODEV;

struct	swdevt swdevt[] = {
	{ NODEV, 0, 0 },
	{ 0, 0, 0 }
};

extern int nfs_mountroot();
int (*mountroot)() = nfs_mountroot;

/* We start with transfer sizes of 4K during boot			*/
/* as the WD8003 has problems to support 8K of back to back packets	*/
struct nfs_diskless nfs_diskless = {
	{ 0 },		/* myif */
	{ 0 },		/* mygateway */
	{		/* swap_args */
	    0,		/* addr */
	    0,		/* sotype */
	    0,		/* proto */
	    0,		/* fh */
	    NFSMNT_WSIZE|NFSMNT_RSIZE,	/* flags */
	    4096,	/* wsize */
	    4096,	/* rsize */
	    0,		/* timeo */
	    0,		/* retrans */
	    0		/* hostname */
	},
	{ 0 },		/* swap_fh */
	{ 0 },		/* swap_saddr */
	{ 0 },		/* swap_hostnam */
	{		/* root_args */
	    0,		/* addr */
	    0,		/* sotype */
	    0,		/* proto */
	    0,		/* fh */
	    NFSMNT_WSIZE|NFSMNT_RSIZE,	/* flags */
	    4096,	/* wsize */
	    4096,	/* rsize */
	    0,		/* timeo */
	    0,		/* retrans */
	    0		/* hostname */
	},
	{ 0 },		/* root_fh */
	{ 0 },		/* root_saddr */
	{ 0 }		/* root_hostnam */
};
