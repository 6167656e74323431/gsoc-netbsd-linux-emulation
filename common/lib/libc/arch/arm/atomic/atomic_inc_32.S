/*	$NetBSD: atomic_inc_32.S,v 1.9 2021/07/28 07:32:20 skrll Exp $	*/
/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas <matt@3am-software.com>
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

#if defined(_ARM_ARCH_6)

ENTRY_NP(_atomic_inc_32)
1:	ldrex	r3, [r0]		/* load old value (return value) */
	adds	r3, r3, #1		/* calculate new value */
	strex	r2, r3, [r0]		/* try to store */
	cmp	r2, #0			/*   succeed? */
	bne	1b			/*     no, try again? */
	RET				/* return new value */
END(_atomic_inc_32)

ATOMIC_OP_ALIAS(atomic_inc_32,_atomic_inc_32)
ATOMIC_OP_ALIAS(atomic_inc_uint,_atomic_inc_32)
ATOMIC_OP_ALIAS(atomic_inc_ulong,_atomic_inc_32)
ATOMIC_OP_ALIAS(atomic_inc_ptr,_atomic_inc_32)
STRONG_ALIAS(_atomic_inc_uint,_atomic_inc_32)
STRONG_ALIAS(_atomic_inc_ulong,_atomic_inc_32)
STRONG_ALIAS(_atomic_inc_ptr,_atomic_inc_32)


ENTRY_NP(_atomic_inc_32_nv)
	mov	ip, r0			/* need r0 for return value */
1:	ldrex	r0, [ip]		/* load old value */
	adds	r0, r0, #1		/* calculate new value (return value) */
	strex	r2, r0, [ip]		/* try to store */
	cmp	r2, #0			/*   succeed? */
	bne	1b			/*     no, try again? */
	RET				/* return new value */
END(_atomic_inc_32_nv)
ATOMIC_OP_ALIAS(atomic_inc_32_nv,_atomic_inc_32_nv)
ATOMIC_OP_ALIAS(atomic_inc_uint_nv,_atomic_inc_32_nv)
ATOMIC_OP_ALIAS(atomic_inc_ulong_nv,_atomic_inc_32_nv)
ATOMIC_OP_ALIAS(atomic_inc_ptr_nv,_atomic_inc_32_nv)
STRONG_ALIAS(_atomic_inc_uint_nv,_atomic_inc_32_nv)
STRONG_ALIAS(_atomic_inc_ulong_nv,_atomic_inc_32_nv)
STRONG_ALIAS(_atomic_inc_ptr_nv,_atomic_inc_32_nv)

#endif /* _ARM_ARCH_6 */
