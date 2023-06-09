/* $NetBSD: atomic_cas_16.S,v 1.4 2021/07/29 10:29:05 skrll Exp $ */

/*-
 * Copyright (c) 2014 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry.
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

#include "atomic_op_asm.h"

ENTRY_NP(_atomic_cas_16)
	mov	x4, x0			/* we need x0 for return value */
1:	ldxrh	w0, [x4]		/* load old value */
	cmp	w0, w1			/*   compare? */
	b.ne	2f
	stxrh	w3, w2, [x4]		/* store new value */
	cbnz	w3, 3f			/*   succeed? nope, try again. */
2:	ret				/* return. */
3:	b	1b
END(_atomic_cas_16)

ATOMIC_OP_ALIAS(atomic_cas_16,_atomic_cas_16)
STRONG_ALIAS(_atomic_cas_short,_atomic_cas_16)
STRONG_ALIAS(_atomic_cas_ushort,_atomic_cas_16)
STRONG_ALIAS(__sync_val_compare_and_swap_2,_atomic_cas_16)

ENTRY_NP(__sync_val_compare_and_swap_2)
	mov	x4, x0			/* we need x0 for return value */
	dmb	ish
1:	ldxrh	w0, [x4]		/* load old value */
	cmp	w0, w1			/*   compare? */
	b.ne	2f
	stxrh	w3, w2, [x4]		/* store new value */
	cbnz	w3, 3f			/*   succeed? nope, try again. */
	dmb	ish
2:	ret				/* return. */
3:	b	1b
END(__sync_val_compare_and_swap_2)
