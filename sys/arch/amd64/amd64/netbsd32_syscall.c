/*	$NetBSD: netbsd32_syscall.c,v 1.20 2007/11/04 11:08:54 dsl Exp $	*/

/*-
 * Copyright (c) 1998, 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: netbsd32_syscall.c,v 1.20 2007/11/04 11:08:54 dsl Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/syscall_stats.h>

#include <uvm/uvm_extern.h>

#include <machine/cpu.h>
#include <machine/psl.h>
#include <machine/userret.h>

void netbsd32_syscall_intern(struct proc *);
void netbsd32_syscall(struct trapframe *);

void
netbsd32_syscall_intern(struct proc *p)
{

	p->p_trace_enabled = trace_is_enabled(p);
	p->p_md.md_syscall = netbsd32_syscall;
}

void
netbsd32_syscall(struct trapframe *frame)
{
	char *params;
	const struct sysent *callp;
	struct proc *p;
	struct lwp *l;
	int error;
	int i;
	register32_t code, args[2 + 8];
	register_t rval[2];
	register_t args64[8];

	l = curlwp;
	p = l->l_proc;

	code = frame->tf_rax;
	callp = p->p_emul->e_sysent;

	uvmexp.syscalls++;
	LWP_CACHE_CREDS(l, p);

	params = (char *)frame->tf_rsp + sizeof(int);

	if (__predict_false(code == SYS_syscall)) {
		/*
		 * Code is first argument, followed by actual args.
		 * Read in all possible arguments while reading in the
		 * actual system call number.
		 */
		error = copyin(params, args + 1, sizeof args - sizeof args[0]);
		if (__predict_false(error != 0))
			goto bad;
		code = args[1] & (SYS_NSYSENT - 1);
		callp += code;
	} else if (__predict_false(code == SYS___syscall)) {
		/*
		 * Like syscall, but code is a quad, so as to maintain
		 * quad alignment for the rest of the arguments.
		 */
		error = copyin(params, args, sizeof args);
		if (__predict_false(error != 0))
			goto bad;
		code = args[0] & (SYS_NSYSENT - 1);
		callp += code;
	} else {
		code &= (SYS_NSYSENT - 1);
		callp += code;
		if (callp->sy_argsize) {
			error = copyin(params, args + 2, callp->sy_argsize);
			if (__predict_false(error != 0))
				goto bad;
			/* Recover 'code' - not in a register */
			code = frame->tf_rax & (SYS_NSYSENT - 1);
		}
	}

	SYSCALL_COUNT(syscall_counts, code);
	SYSCALL_TIME_SYS_ENTRY(l, syscall_times, code);
	if (__predict_false(p->p_trace_enabled)) {
		int narg = callp->sy_argsize >> 2;
		for (i = 0; i < narg; i++)
			args64[i] = args[i + 2];
		error = trace_enter(l, code, code, NULL, args64);
		if (__predict_false(error != 0))
			goto out;
	}

	rval[0] = 0;
	rval[1] = 0;
	KERNEL_LOCK(1, l);
	error = (*callp->sy_call)(l, args + 2, rval);
	KERNEL_UNLOCK_LAST(l);

out:
	if (__predict_true(error == 0)) {
		frame->tf_rax = rval[0];
		frame->tf_rdx = rval[1];
		frame->tf_rflags &= ~PSL_C;	/* carry bit */
	} else {
		switch (error) {
		case ERESTART:
			/*
			 * The offset to adjust the PC by depends on whether we
			 * entered the kernel through the trap or call gate.
			 * We saved the size of the instruction in tf_err
			 * on entry.
			 */
			frame->tf_rip -= frame->tf_err;
			break;
		case EJUSTRETURN:
			/* nothing to do */
			break;
		default:
		bad:
			frame->tf_rax = error;
			frame->tf_rflags |= PSL_C;	/* carry bit */
			break;
		}
	}

	if (__predict_false(p->p_trace_enabled)) {
		/* Recover 'code' - the compiler doesn't assign it a register */
		code = callp - p->p_emul->e_sysent;
		trace_exit(l, code, args64, rval, error);
	}
	SYSCALL_TIME_SYS_EXIT(l);
	userret(l);
}
