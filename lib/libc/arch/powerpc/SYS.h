/*	$NetBSD: SYS.h,v 1.1 1997/03/29 20:55:51 thorpej Exp $	*/

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	from: @(#)SYS.h	5.5 (Berkeley) 5/7/91
 */

#include <machine/asm.h>
#include <sys/syscall.h>

#ifdef __STDC__

#define	SYSCALL_NOERROR(x)	.text				;\
				.align	2			;\
			ENTRY(x)				;\
				li	0,(SYS_ ## x)		;\
				sc

#define	PSEUDO(x,y)		.text				;\
				.align	2			;\
			ENTRY(x)				;\
				li	0,(SYS_ ## y)		;\
				sc				;\
				blr

#else /* !__STDC__ */

#define	SYSCALL_NOERROR(x)	.text				;\
				.align	2			;\
			ENTRY(x)				;\
				li	0,(SYS_/**/x)		;\
				sc

#define	PSEUDO(x,y)		.text				;\
				.align	2			;\
			ENTRY(x)				;\
				li	0,(SYS_/**/y)		;\
				sc				;\
				blr

#endif

#define	RSYSCALL_NOERROR(x)	SYSCALL_NOERROR(x)		;\
				blr

#define	SYSCALL(x)		.text				;\
				.align	2			;\
			2:	b	PIC_PLT(cerror)		;\
				SYSCALL_NOERROR(x)		;\
				bso	2b

#define	RSYSCALL(x)		SYSCALL_NOERROR(x)		;\
				bnslr				;\
				b	PIC_PLT(cerror)
