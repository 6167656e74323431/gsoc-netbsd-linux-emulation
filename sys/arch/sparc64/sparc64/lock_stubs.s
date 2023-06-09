/*	$NetBSD: lock_stubs.s,v 1.13 2023/02/20 13:30:36 riastradh Exp $	*/

/*-
 * Copyright (c) 2002, 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe and Andrew Doran.
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

#include "opt_multiprocessor.h"
#include "opt_lockdebug.h"

#include <machine/param.h>
#include <machine/asm.h>

#include "assym.h"

#undef CURLWP
#define	CURLWP	(CPUINFO_VA+CI_CURLWP)

#if defined(MULTIPROCESSOR)
#define	MB_ACQ	membar #LoadLoad | #LoadStore
#define	MB_REL	membar #LoadStore | #StoreStore
#else
#define	MB_ACQ	/* nothing */
#define	MB_REL	/* nothing */
#endif

#if !defined(LOCKDEBUG)

/*
 * void mutex_enter(kmutex_t *);
 */
.align	32
ENTRY(mutex_enter)
	sethi	%hi(CURLWP), %o1
	LDPTR	[%o1 + %lo(CURLWP)], %o1	! current thread
	CASPTR	[%o0], %g0, %o1			! compare-and-swap
	MB_ACQ
	brnz,pn	%o1, 1f				! lock was unowned?
	 nop
	retl					! - yes, done
	 nop
1:	ba	_C_LABEL(mutex_vector_enter)	! nope, do it the
	 nop					! hard way

/*
 * void mutex_exit(kmutex_t *);
 *
 * XXX This should use a restartable sequence.  See mutex_vector_enter().
 */
.align	32
ENTRY(mutex_exit)
	sethi	%hi(CURLWP), %o1
	LDPTR	[%o1 + %lo(CURLWP)], %o1	! current thread
	clr	%o2				! new value (0)
	MB_REL
	CASPTR	[%o0], %o1, %o2			! compare-and-swap
	cmp	%o1, %o2
	bne,pn	CCCR, 1f			! nope, hard case
	 nop
	retl
	 nop
1:	ba _C_LABEL(mutex_vector_exit)
	 nop

#endif	/* !LOCKDEBUG */
