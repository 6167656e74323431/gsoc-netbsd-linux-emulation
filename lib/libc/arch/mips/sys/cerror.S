/*	$NetBSD: cerror.S,v 1.21 2022/12/03 14:04:39 skrll Exp $	*/

/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 */

#include "SYS.h"

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
	RCSID("from: @(#)cerror.s	8.1 (Berkeley) 6/16/93")
#else
	RCSID("$NetBSD: cerror.S,v 1.21 2022/12/03 14:04:39 skrll Exp $")
#endif
#endif /* LIBC_SCCS and not lint */

#ifdef __PIC__
	.protected	__cerror
#endif

#ifdef _REENTRANT
	.globl	_C_LABEL(__errno)
NESTED_NOPROFILE(__cerror, CALLFRAME_SIZ, ra)
	.mask	0x80000000, (CALLFRAME_RA - CALLFRAME_SIZ)
	PIC_PROLOGUE(__cerror)		# saves caller gp in t3 (n32/n64)
	PTR_SUBU	sp, CALLFRAME_SIZ
	PTR_S		ra, CALLFRAME_RA(sp)
	INT_S		v0, CALLFRAME_S0(sp)	# save errno value
#if defined(__mips_n32) || defined(__mips_n64)
	PTR_S		t3, CALLFRAME_GP(sp)	# save caller gp (in t3)
#endif

	SAVE_GP(CALLFRAME_GP)

	PTR_LA		t9, _C_LABEL(__errno)	# locate address of errno

	jalr		t9			# __errno()

#if defined(__mips_n32) || defined(__mips_n64)
	PTR_L		gp, CALLFRAME_GP(sp)	# restore caller gp
#endif
	INT_L		t0, CALLFRAME_S0(sp)
	PTR_L		ra, CALLFRAME_RA(sp)
	INT_S		t0, 0(v0)		# update errno value
	PTR_ADDU	sp, CALLFRAME_SIZ
	li		v0, -1
	li		v1, -1

	# Note we don't use PIC_RETURN() here as the GP is stored
	# on the stack and not in the t3 reg (for the n32/n64 case).
	j		ra
END(__cerror)
#else
	.globl	_C_LABEL(errno)
LEAF_NOPROFILE(__cerror)
	PIC_PROLOGUE(__cerror)
	INT_S		v0, _C_LABEL(errno)
	li		v0, -1
	li		v1, -1
	PIC_RETURN()
END(__cerror)
#endif /* _REENTRANT */
