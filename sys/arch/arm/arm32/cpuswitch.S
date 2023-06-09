/*	$NetBSD: cpuswitch.S,v 1.107 2023/03/01 08:17:53 riastradh Exp $	*/

/*
 * Copyright 2003 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Steve C. Woodford for Wasabi Systems, Inc.
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
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright (c) 1994-1998 Mark Brinicombe.
 * Copyright (c) 1994 Brini.
 * All rights reserved.
 *
 * This code is derived from software written for Brini by Mark Brinicombe
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
 *	This product includes software developed by Brini.
 * 4. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BRINI ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL BRINI OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * RiscBSD kernel project
 *
 * cpuswitch.S
 *
 * cpu switching functions
 *
 * Created      : 15/10/94
 */

#include "opt_armfpe.h"
#include "opt_cpuoptions.h"
#include "opt_kasan.h"
#include "opt_lockdebug.h"
#include "opt_multiprocessor.h"

#include "assym.h"
#include <arm/asm.h>
#include <arm/locore.h>

	RCSID("$NetBSD: cpuswitch.S,v 1.107 2023/03/01 08:17:53 riastradh Exp $")

/* LINTSTUB: include <sys/param.h> */

#ifdef FPU_VFP
	.fpu vfpv2
#endif

#undef IRQdisable
#undef IRQenable

/*
 * New experimental definitions of IRQdisable and IRQenable
 * These keep FIQ's enabled since FIQ's are special.
 */

#ifdef _ARM_ARCH_6
#define	IRQdisable	cpsid	i
#define	IRQenable	cpsie	i
#else
#define IRQdisable \
	mrs	r14, cpsr ; \
	orr	r14, r14, #(I32_bit) ; \
	msr	cpsr_c, r14

#define IRQenable \
	mrs	r14, cpsr ; \
	bic	r14, r14, #(I32_bit) ; \
	msr	cpsr_c, r14

#endif

	.text

/*
 * struct lwp *
 * cpu_switchto(struct lwp *current, struct lwp *next)
 *
 * Switch to the specified next LWP
 * Arguments:
 *
 *	r0	'struct lwp *' of the current LWP
 *	r1	'struct lwp *' of the LWP to switch to
 *	r2	returning
 */
ENTRY(cpu_switchto)
	mov	ip, sp
	push	{r4-r7, ip, lr}

	/* move lwps into callee saved registers */
	mov	r6, r1
	mov	r4, r0

#ifdef TPIDRPRW_IS_CURCPU
	GET_CURCPU(r5)
#else
	ldr	r5, [r6, #L_CPU]		/* get cpu from new lwp */
#endif

	/* rem: r4 = old lwp */
	/* rem: r5 = curcpu() */
	/* rem: r6 = new lwp */
	/* rem: interrupts are enabled */

	/* Save old context */

	/* Get the user structure for the old lwp. */
	ldr	r7, [r4, #(L_PCB)]

	/* Save all the registers in the old lwp's pcb */
#if defined(_ARM_ARCH_DWORD_OK)
	strd	r8, r9, [r7, #(PCB_R8)]
	strd	r10, r11, [r7, #(PCB_R10)]
	strd	r12, r13, [r7, #(PCB_R12)]
#else
	add	r0, r7, #(PCB_R8)
	stmia	r0, {r8-r13}
#endif

#ifdef _ARM_ARCH_6
	/*
	 * Save user read/write thread/process id register
	 */
	mrc	p15, 0, r0, c13, c0, 2
	str	r0, [r7, #(PCB_USER_PID_RW)]
#endif
	/*
	 * NOTE: We can now use r8-r13 until it is time to restore
	 * them for the new process.
	 */

	/* Restore saved context */

	/* rem: r4 = old lwp */
	/* rem: r5 = curcpu() */
	/* rem: r6 = new lwp */

	IRQdisable
#if defined(TPIDRPRW_IS_CURLWP)
	mcr	p15, 0, r6, c13, c0, 4		/* set current lwp */
#endif

	/*
	 * Issue barriers to coordinate mutex_exit on this CPU with
	 * mutex_vector_enter on another CPU.
	 *
	 * 1. Any prior mutex_exit by oldlwp must be visible to other
	 *    CPUs before we set ci_curlwp := newlwp on this one,
	 *    requiring a store-before-store barrier.
	 *
	 * 2. ci_curlwp := newlwp must be visible on all other CPUs
	 *    before any subsequent mutex_exit by newlwp can even test
	 *    whether there might be waiters, requiring a
	 *    store-before-load barrier.
	 *
	 * See kern_mutex.c for details -- this is necessary for
	 * adaptive mutexes to detect whether the lwp is on the CPU in
	 * order to safely block without requiring atomic r/m/w in
	 * mutex_exit.
	 */

	/* We have a new curlwp now so make a note of it */
#ifdef _ARM_ARCH_7
	dmb				/* store-before-store */
#endif
	str	r6, [r5, #(CI_CURLWP)]
#ifdef _ARM_ARCH_7
	dmb				/* store-before-load */
#endif

	/* Get the new pcb */
	ldr	r7, [r6, #(L_PCB)]

	/* make sure we are using the new lwp's stack */
	ldr	sp, [r7, #(PCB_KSP)]

	/* At this point we can allow IRQ's again. */
	IRQenable

	/* rem: r4 = old lwp */
	/* rem: r5 = curcpu() */
	/* rem: r6 = new lwp */
	/* rem: r7 = new pcb */
	/* rem: interrupts are enabled */

	/*
	 * If we are switching to a system lwp, don't bother restoring
	 * thread or vfp registers and skip the ras check.
	 */
	ldr	r0, [r6, #(L_FLAG)]
	tst	r0, #(LW_SYSTEM)
	bne	.Lswitch_do_restore

#ifdef _ARM_ARCH_6
	/*
	 * Restore user thread/process id registers
	 */
	ldr	r0, [r7, #(PCB_USER_PID_RW)]
	mcr	p15, 0, r0, c13, c0, 2
	ldr	r0, [r6, #(L_PRIVATE)]
	mcr	p15, 0, r0, c13, c0, 3
#endif

#ifdef FPU_VFP
	/*
	 * If we have a VFP, we need to load FPEXC.
	 */
	ldr	r0, [r5, #(CI_VFP_ID)]
	cmp	r0, #0
	ldrne	r0, [r7, #(PCB_VFP_FPEXC)]
	vmsrne	fpexc, r0
#endif

	/*
	 * Check for restartable atomic sequences (RAS).
	 */
	ldr	r0, [r6, #(L_PROC)]	/* fetch the proc for ras_lookup */
	ldr	r2, [r0, #(P_RASLIST)]
	cmp	r2, #0			/* p->p_nras == 0? */
	beq	.Lswitch_do_restore

	/* we can use r8 since we haven't restored saved registers yet. */
	ldr	r8, [r6, #(L_MD_TF)]	/* r1 = trapframe (used below) */
	ldr	r1, [r8, #(TF_PC)]	/* second ras_lookup() arg */
	bl	_C_LABEL(ras_lookup)
	cmn	r0, #1			/* -1 means "not in a RAS" */
	strne	r0, [r8, #(TF_PC)]

	/* rem: r4 = old lwp */
	/* rem: r5 = curcpu() */
	/* rem: r6 = new lwp */
	/* rem: r7 = new pcb */

.Lswitch_do_restore:
	/* Restore all the saved registers */
#ifdef __XSCALE__
	ldr	r8, [r7, #(PCB_R8)]
	ldr	r9, [r7, #(PCB_R9)]
	ldr	r10, [r7, #(PCB_R10)]
	ldr	r11, [r7, #(PCB_R11)]
	ldr	r12, [r7, #(PCB_R12)]
#elif defined(_ARM_ARCH_DWORD_OK)
	ldrd	r8, r9, [r7, #(PCB_R8)]
	ldrd	r10, r11, [r7, #(PCB_R10)]
	ldr	r12, [r7, #(PCB_R12)]
#else
	add	r0, r7, #PCB_R8
	ldmia	r0, {r8-r12}
#endif

	/* Record the old lwp for pmap_activate()'s benefit */
#ifndef ARM_MMU_EXTENDED
	str	r4, [r5, #CI_LASTLWP]
#endif

	/* cpu_switchto returns the old lwp */
	mov	r0, r4
	/* lwp_trampoline expects new lwp as its second argument */
	mov	r1, r6

#ifdef _ARM_ARCH_7
	clrex				/* cause any subsequent STREX* to fail */
#endif

	/*
	 * Pull the registers that got pushed when cpu_switchto() was called,
	 * and return.
	 */
	pop	{r4-r7, ip, pc}

END(cpu_switchto)

ENTRY_NP(lwp_trampoline)
	/*
	 * cpu_switchto gives us:
	 *	arg0(r0) = old lwp
	 *	arg1(r1) = new lwp
	 * setup by cpu_lwp_fork:
	 *	r4 = func to call
	 *	r5 = arg to func
	 *	r6 = <unused>
	 *	r7 = spsr mode
	 */
	bl	_C_LABEL(lwp_startup)

	mov	fp, #0			/* top stack frame */
	mov	r0, r5
	mov	r1, sp
#ifdef _ARM_ARCH_5
	blx	r4
#else
	mov	lr, pc
	mov	pc, r4
#endif

	GET_CPSR(r0)
	CPSID_I(r0, r0)			/* Kill irq's */

	/* for DO_AST */
	GET_CURX(r4, r5)		/* r4 = curcpu, r5 = curlwp */
	DO_AST_AND_RESTORE_ALIGNMENT_FAULTS
	PULLFRAME

	movs	pc, lr			/* Exit */
END(lwp_trampoline)

AST_ALIGNMENT_FAULT_LOCALS

#ifdef __HAVE_FAST_SOFTINTS
/*
 *	Called at IPL_HIGH
 *	r0 = new lwp
 *	r1 = ipl for softint_dispatch
 */
ENTRY_NP(softint_switch)
	push	{r4, r6, r7, lr}

	ldr	r7, [r0, #L_CPU]	/* get curcpu */
#if defined(TPIDRPRW_IS_CURLWP)
	mrc	p15, 0, r4, c13, c0, 4	/* get old lwp */
#else
	ldr	r4, [r7, #(CI_CURLWP)]	/* get old lwp */
#endif
	mrs	r6, cpsr		/* we need to save this */

	/*
	 * If the soft lwp blocks, it needs to return to softint_tramp
	 */
	mov	r2, sp			/* think ip */
	adr	r3, softint_tramp	/* think lr */
	push	{r2-r3}
	push	{r4-r7}

	mov	r5, r0			/* save new lwp */

	ldr	r2, [r4, #(L_PCB)]	/* get old lwp's pcb */

	/* Save all the registers into the old lwp's pcb */
#if defined(__XSCALE__) || defined(_ARM_ARCH_6)
	strd	r8, r9, [r2, #(PCB_R8)]
	strd	r10, r11, [r2, #(PCB_R10)]
	strd	r12, r13, [r2, #(PCB_R12)]
#else
	add	r3, r2, #(PCB_R8)
	stmia	r3, {r8-r13}
#endif

#ifdef _ARM_ARCH_6
	/*
	 * Save user read/write thread/process id register in case it was
	 * set in userland.
	 */
	mrc	p15, 0, r0, c13, c0, 2
	str	r0, [r2, #(PCB_USER_PID_RW)]
#endif

	/* this is an invariant so load before disabling intrs */
	ldr	r2, [r5, #(L_PCB)]	/* get new lwp's pcb */

	IRQdisable
	/*
	 * We're switching to a bound LWP so its l_cpu is already correct.
	 */
#if defined(TPIDRPRW_IS_CURLWP)
	mcr	p15, 0, r5, c13, c0, 4	/* save new lwp */
#endif
#ifdef _ARM_ARCH_7
	dmb				/* for mutex_enter; see cpu_switchto */
#endif
	str	r5, [r7, #(CI_CURLWP)]	/* save new lwp */
	/*
	 * No need for barrier after ci->ci_curlwp = softlwp -- when we
	 * enter a softint lwp, it can't be holding any mutexes, so it
	 * can't release any until after it has acquired them, so we
	 * need not participate in the protocol with mutex_vector_enter
	 * barriers here.
	 */

#ifdef KASAN
	mov	r0, r5
	bl	_C_LABEL(kasan_softint)
#endif

	/*
	 * Normally, we'd get {r8-r13} but since this is a softint lwp
	 * its existing state doesn't matter.  We start the stack just
	 * below the trapframe.
	 */
	ldr	sp, [r5, #(L_MD_TF)]	/* get new lwp's stack ptr */

	/* At this point we can allow IRQ's again. */
	IRQenable
					/* r1 still has ipl */
	mov	r0, r4			/* r0 has pinned (old) lwp */
	bl	_C_LABEL(softint_dispatch)
	/*
	 * If we've returned, we need to change everything back and return.
	 */
	ldr	r2, [r4, #(L_PCB)]	/* get pinned lwp's pcb */

	/*
	 * We don't need to restore all the registers since another lwp was
	 * never executed.  But we do need the SP from the formerly pinned lwp.
	 */

	IRQdisable
#if defined(TPIDRPRW_IS_CURLWP)
	mcr	p15, 0, r4, c13, c0, 4	/* restore pinned lwp */
#endif
#ifdef _ARM_ARCH_7
	dmb				/* for mutex_enter; see cpu_switchto */
#endif
	str	r4, [r7, #(CI_CURLWP)]	/* restore pinned lwp */
#ifdef _ARM_ARCH_7
	dmb				/* for mutex_enter; see cpu_switchto */
#endif
	ldr	sp, [r2, #(PCB_KSP)]	/* now running on the old stack. */

	/* At this point we can allow IRQ's again. */
	msr	cpsr_c, r6

	/*
	 * Grab the registers that got pushed at the start and return.
	 */
	pop	{r4-r7, ip, lr}		/* eat switch frame */
	pop	{r4, r6, r7, pc}	/* pop stack and return */

END(softint_switch)

/*
 * r0 = previous LWP (the soft lwp)
 * r4 = original LWP (the current lwp)
 * r6 = original CPSR
 * r7 = curcpu()
 */
ENTRY_NP(softint_tramp)
	ldr	r3, [r7, #(CI_MTX_COUNT)]	/* readjust after mi_switch */
	add	r3, r3, #1
	str	r3, [r7, #(CI_MTX_COUNT)]

	msr	cpsr_c, r6			/* restore interrupts */
	pop	{r4, r6, r7, pc}		/* pop stack and return */
END(softint_tramp)
#endif /* __HAVE_FAST_SOFTINTS */
