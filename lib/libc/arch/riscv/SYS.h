/*	$NetBSD: SYS.h,v 1.4 2023/05/07 12:41:47 skrll Exp $ */

/*-
 * Copyright (c) 2014,2022 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry, and Nick Hudson.
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

#include <sys/syscall.h>
#include <machine/asm.h>

#define SYSTRAP(x)							\
	li	t6, SYS_ ## x;						\
	ecall

#define	JUMP_TO_CERROR()						\
	.option push							;\
	.option norelax							;\
	tail	_C_LABEL(__cerror)					;\
	.option pop

#define	SYSTRAP_NOERROR(x)						\
	SYSTRAP(x)							;\
	nop; nop		/* size of ... 			*/	;\
	nop; nop		/*     JUMP_TO_CERROR		*/	;\

/*
 * Do a syscall that cannot fail (sync, get{p,u,g,eu,eg)id)
 */
#define RSYSCALL_NOERROR(x)						\
	PSEUDO_NOERROR(x,x)

/*
 * Do a normal syscall.
 */
#define RSYSCALL(x)							\
	PSEUDO(x,x)

/*
 * Do a syscall that has an internal name and a weak external alias.
 */
#define	WSYSCALL(weak,strong)						\
	WEAK_ALIAS(weak,strong)						;\
	PSEUDO(strong,weak)

/*
 * Do a renamed or pseudo syscall (e.g., _exit()), where the entrypoint
 * and syscall name are not the same.
 */
#define PSEUDO_NOERROR(x,y)						\
ENTRY(x);								;\
	SYSTRAP_NOERROR(y)						;\
	ret			/* success */				;\
	END(x)

#define PSEUDO(x,y)							\
ENTRY(x);								;\
	SYSTRAP(y)							;\
	JUMP_TO_CERROR()	/* error */				;\
	ret			/* success */				;\
	END(x)
