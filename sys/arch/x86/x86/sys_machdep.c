/*	$NetBSD: sys_machdep.c,v 1.58 2022/08/20 23:49:31 riastradh Exp $	*/

/*
 * Copyright (c) 1998, 2007, 2009, 2017 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum, by Andrew Doran, and by Maxime Villard.
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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sys_machdep.c,v 1.58 2022/08/20 23:49:31 riastradh Exp $");

#include "opt_mtrr.h"
#include "opt_user_ldt.h"
#include "opt_compat_netbsd.h"
#include "opt_xen.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/buf.h>
#include <sys/signal.h>
#include <sys/malloc.h>
#include <sys/kmem.h>
#include <sys/kauth.h>
#include <sys/cpu.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>

#include <uvm/uvm_extern.h>

#include <machine/cpufunc.h>
#include <machine/gdt.h>
#include <machine/psl.h>
#include <machine/reg.h>
#include <machine/sysarch.h>
#include <machine/mtrr.h>
#include <machine/pmap_private.h>

#if defined(__x86_64__) || defined(XENPV)
#undef	IOPERM	/* not implemented */
#else
#define	IOPERM
#endif

#if defined(XENPV) && defined(USER_LDT)
#error "USER_LDT not supported on XENPV"
#endif

extern struct vm_map *kernel_map;

static int x86_get_ioperm(struct lwp *, void *, register_t *);
static int x86_set_ioperm(struct lwp *, void *, register_t *);
static int x86_set_sdbase32(void *, char, lwp_t *, bool);
int x86_set_sdbase(void *, char, lwp_t *, bool);
static int x86_get_sdbase32(void *, char);
int x86_get_sdbase(void *, char);

#ifdef i386
static int
x86_get_ldt(struct lwp *l, void *args, register_t *retval)
{
#ifndef USER_LDT
	return EINVAL;
#else
	struct x86_get_ldt_args ua;
	union descriptor *cp;
	int error;

	if ((error = copyin(args, &ua, sizeof(ua))) != 0)
		return error;

	if (ua.num < 0 || ua.num > MAX_USERLDT_SLOTS)
		return EINVAL;

	cp = malloc(ua.num * sizeof(union descriptor), M_TEMP, M_WAITOK);
	if (cp == NULL)
		return ENOMEM;

	error = x86_get_ldt1(l, &ua, cp);
	*retval = ua.num;
	if (error == 0)
		error = copyout(cp, ua.desc, ua.num * sizeof(*cp));

	free(cp, M_TEMP);
	return error;
#endif
}
#endif

int
x86_get_ldt1(struct lwp *l, struct x86_get_ldt_args *ua, union descriptor *cp)
{
#ifndef USER_LDT
	return EINVAL;
#else
	int error;
	struct proc *p = l->l_proc;
	pmap_t pmap = p->p_vmspace->vm_map.pmap;
	int nldt, num;
	union descriptor *lp;

#ifdef __x86_64__
	const size_t min_ldt_size = LDT_SIZE;
#else
	const size_t min_ldt_size = NLDT * sizeof(union descriptor);
#endif

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_LDT_GET,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	if (ua->start < 0 || ua->num < 0 ||
	    ua->start > MAX_USERLDT_SLOTS || ua->num > MAX_USERLDT_SLOTS ||
	    ua->start + ua->num > MAX_USERLDT_SLOTS)
		return EINVAL;

	if (ua->start * sizeof(union descriptor) < min_ldt_size)
		return EINVAL;

	mutex_enter(&cpu_lock);

	if (pmap->pm_ldt != NULL) {
		nldt = MAX_USERLDT_SIZE / sizeof(*lp);
		lp = pmap->pm_ldt;
	} else {
#ifdef __x86_64__
		nldt = LDT_SIZE / sizeof(*lp);
#else
		nldt = NLDT;
#endif
		lp = (union descriptor *)ldtstore;
	}

	if (ua->start > nldt) {
		mutex_exit(&cpu_lock);
		return EINVAL;
	}

	lp += ua->start;
	num = uimin(ua->num, nldt - ua->start);
	ua->num = num;

	memcpy(cp, lp, num * sizeof(union descriptor));
	mutex_exit(&cpu_lock);

	return 0;
#endif
}

#ifdef i386
static int
x86_set_ldt(struct lwp *l, void *args, register_t *retval)
{
#ifndef USER_LDT
	return EINVAL;
#else
	struct x86_set_ldt_args ua;
	union descriptor *descv;
	int error;

	if ((error = copyin(args, &ua, sizeof(ua))) != 0)
		return error;

	if (ua.num < 0 || ua.num > MAX_USERLDT_SLOTS)
		return EINVAL;

	descv = malloc(sizeof (*descv) * ua.num, M_TEMP, M_WAITOK);
	error = copyin(ua.desc, descv, sizeof (*descv) * ua.num);
	if (error == 0)
		error = x86_set_ldt1(l, &ua, descv);
	*retval = ua.start;

	free(descv, M_TEMP);
	return error;
#endif
}
#endif

int
x86_set_ldt1(struct lwp *l, struct x86_set_ldt_args *ua,
    union descriptor *descv)
{
#ifndef USER_LDT
	return EINVAL;
#else
	int error, i, n, old_sel, new_sel;
	struct proc *p = l->l_proc;
	pmap_t pmap = p->p_vmspace->vm_map.pmap;
	union descriptor *old_ldt, *new_ldt;

#ifdef __x86_64__
	const size_t min_ldt_size = LDT_SIZE;
#else
	const size_t min_ldt_size = NLDT * sizeof(union descriptor);
#endif

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_LDT_SET,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	if (ua->start < 0 || ua->num < 0 ||
	    ua->start > MAX_USERLDT_SLOTS || ua->num > MAX_USERLDT_SLOTS ||
	    ua->start + ua->num > MAX_USERLDT_SLOTS)
		return EINVAL;

	if (ua->start * sizeof(union descriptor) < min_ldt_size)
		return EINVAL;

	/* Check descriptors for access violations. */
	for (i = 0; i < ua->num; i++) {
		union descriptor *desc = &descv[i];

#ifdef __x86_64__
		if (desc->sd.sd_long != 0)
			return EACCES;
#endif

		switch (desc->sd.sd_type) {
		case SDT_SYSNULL:
			desc->sd.sd_p = 0;
			break;
		case SDT_MEMEC:
		case SDT_MEMEAC:
		case SDT_MEMERC:
		case SDT_MEMERAC:
			/* Must be "present" if executable and conforming. */
			if (desc->sd.sd_p == 0)
				return EACCES;
			break;
		case SDT_MEMRO:
		case SDT_MEMROA:
		case SDT_MEMRW:
		case SDT_MEMRWA:
		case SDT_MEMROD:
		case SDT_MEMRODA:
		case SDT_MEMRWD:
		case SDT_MEMRWDA:
		case SDT_MEME:
		case SDT_MEMEA:
		case SDT_MEMER:
		case SDT_MEMERA:
			break;
		default:
			return EACCES;
		}

		if (desc->sd.sd_p != 0) {
			/* Only user (ring-3) descriptors may be present. */
			if (desc->sd.sd_dpl != SEL_UPL)
				return EACCES;
		}
	}

	/*
	 * Install selected changes.
	 */

	/* Allocate a new LDT. */
	new_ldt = (union descriptor *)uvm_km_alloc(kernel_map,
	    MAX_USERLDT_SIZE, 0, UVM_KMF_WIRED | UVM_KMF_ZERO | UVM_KMF_WAITVA);

	mutex_enter(&cpu_lock);

	/* Copy existing entries, if any. */
	if (pmap->pm_ldt != NULL) {
		old_ldt = pmap->pm_ldt;
		old_sel = pmap->pm_ldt_sel;
		memcpy(new_ldt, old_ldt, MAX_USERLDT_SIZE);
	} else {
		old_ldt = NULL;
		old_sel = -1;
		memcpy(new_ldt, ldtstore, min_ldt_size);
	}

	/* Apply requested changes. */
	for (i = 0, n = ua->start; i < ua->num; i++, n++) {
		new_ldt[n] = descv[i];
	}

	/* Allocate LDT selector. */
	new_sel = ldt_alloc(new_ldt, MAX_USERLDT_SIZE);
	if (new_sel == -1) {
		mutex_exit(&cpu_lock);
		uvm_km_free(kernel_map, (vaddr_t)new_ldt, MAX_USERLDT_SIZE,
		    UVM_KMF_WIRED);
		return ENOMEM;
	}

	/* All changes are now globally visible.  Swap in the new LDT. */
	atomic_store_relaxed(&pmap->pm_ldt_sel, new_sel);
	/* membar_store_store for pmap_fork() to read these unlocked safely */
	membar_producer();
	atomic_store_relaxed(&pmap->pm_ldt, new_ldt);

	/* Switch existing users onto new LDT. */
	pmap_ldt_sync(pmap);

	/* Free existing LDT (if any). */
	if (old_ldt != NULL) {
		ldt_free(old_sel);
		/* exit the mutex before free */
		mutex_exit(&cpu_lock);
		uvm_km_free(kernel_map, (vaddr_t)old_ldt, MAX_USERLDT_SIZE,
		    UVM_KMF_WIRED);
	} else {
		mutex_exit(&cpu_lock);
	}

	return error;
#endif
}

int
x86_iopl(struct lwp *l, void *args, register_t *retval)
{
	int error;
	struct x86_iopl_args ua;
#ifdef XENPV
	int iopl;
#else
	struct trapframe *tf = l->l_md.md_regs;
#endif

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_IOPL,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	if ((error = copyin(args, &ua, sizeof(ua))) != 0)
		return error;

#ifdef XENPV
	if (ua.iopl)
		iopl = SEL_UPL;
	else
		iopl = SEL_KPL;

    {
	struct pcb *pcb;

	pcb = lwp_getpcb(l);
	pcb->pcb_iopl = iopl;

	/* Force the change at ring 0. */
	struct physdev_set_iopl set_iopl;
	set_iopl.iopl = iopl;
	HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);
    }
#elif defined(__x86_64__)
	if (ua.iopl)
		tf->tf_rflags |= PSL_IOPL;
	else
		tf->tf_rflags &= ~PSL_IOPL;
#else
	if (ua.iopl)
		tf->tf_eflags |= PSL_IOPL;
	else
		tf->tf_eflags &= ~PSL_IOPL;
#endif

	return 0;
}

static int
x86_get_ioperm(struct lwp *l, void *args, register_t *retval)
{
#ifdef IOPERM
	int error;
	struct pcb *pcb = lwp_getpcb(l);
	struct x86_get_ioperm_args ua;
	void *dummymap = NULL;
	void *iomap;

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_IOPERM_GET,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	if ((error = copyin(args, &ua, sizeof(ua))) != 0)
		return error;

	iomap = pcb->pcb_iomap;
	if (iomap == NULL) {
		iomap = dummymap = kmem_alloc(IOMAPSIZE, KM_SLEEP);
		memset(dummymap, 0xff, IOMAPSIZE);
	}
	error = copyout(iomap, ua.iomap, IOMAPSIZE);
	if (dummymap != NULL) {
		kmem_free(dummymap, IOMAPSIZE);
	}
	return error;
#else
	return EINVAL;
#endif
}

static int
x86_set_ioperm(struct lwp *l, void *args, register_t *retval)
{
#ifdef IOPERM
	struct cpu_info *ci;
	int error;
	struct pcb *pcb = lwp_getpcb(l);
	struct x86_set_ioperm_args ua;
	void *new;
	void *old;

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_IOPERM_SET,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	if ((error = copyin(args, &ua, sizeof(ua))) != 0)
		return error;

	new = kmem_alloc(IOMAPSIZE, KM_SLEEP);
	error = copyin(ua.iomap, new, IOMAPSIZE);
	if (error) {
		kmem_free(new, IOMAPSIZE);
		return error;
	}
	old = pcb->pcb_iomap;
	pcb->pcb_iomap = new;
	if (old != NULL) {
		kmem_free(old, IOMAPSIZE);
	}

	CTASSERT(offsetof(struct cpu_tss, iomap) -
	    offsetof(struct cpu_tss, tss) == IOMAP_VALIDOFF);

	kpreempt_disable();
	ci = curcpu();
	memcpy(ci->ci_tss->iomap, pcb->pcb_iomap, IOMAPSIZE);
	ci->ci_tss->tss.tss_iobase = IOMAP_VALIDOFF << 16;
	kpreempt_enable();

	return error;
#else
	return EINVAL;
#endif
}

static int
x86_get_mtrr(struct lwp *l, void *args, register_t *retval)
{
#ifdef MTRR
	struct x86_get_mtrr_args ua;
	int error, n;

	if (mtrr_funcs == NULL)
		return ENOSYS;

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_MTRR_GET,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	error = copyin(args, &ua, sizeof ua);
	if (error != 0)
		return error;

	error = copyin(ua.n, &n, sizeof n);
	if (error != 0)
		return error;

	KERNEL_LOCK(1, NULL);
	error = mtrr_get(ua.mtrrp, &n, l->l_proc, MTRR_GETSET_USER);
	KERNEL_UNLOCK_ONE(NULL);

	copyout(&n, ua.n, sizeof (int));

	return error;
#else
	return EINVAL;
#endif
}

static int
x86_set_mtrr(struct lwp *l, void *args, register_t *retval)
{
#ifdef MTRR
	int error, n;
	struct x86_set_mtrr_args ua;

	if (mtrr_funcs == NULL)
		return ENOSYS;

	error = kauth_authorize_machdep(l->l_cred, KAUTH_MACHDEP_MTRR_SET,
	    NULL, NULL, NULL, NULL);
	if (error)
		return error;

	error = copyin(args, &ua, sizeof ua);
	if (error != 0)
		return error;

	error = copyin(ua.n, &n, sizeof n);
	if (error != 0)
		return error;

	KERNEL_LOCK(1, NULL);
	error = mtrr_set(ua.mtrrp, &n, l->l_proc, MTRR_GETSET_USER);
	if (n != 0)
		mtrr_commit();
	KERNEL_UNLOCK_ONE(NULL);

	copyout(&n, ua.n, sizeof n);

	return error;
#else
	return EINVAL;
#endif
}

#ifdef __x86_64__
#define pcb_fsd pcb_fs
#define pcb_gsd pcb_gs
#define segment_descriptor mem_segment_descriptor
#endif

static int
x86_set_sdbase32(void *arg, char which, lwp_t *l, bool direct)
{
	struct trapframe *tf = l->l_md.md_regs;
	union descriptor usd;
	struct pcb *pcb;
	uint32_t base;
	int error;

	if (direct) {
		base = (vaddr_t)arg;
	} else {
		error = copyin(arg, &base, sizeof(base));
		if (error != 0)
			return error;
	}

	memset(&usd, 0, sizeof(usd));
	usd.sd.sd_lobase = base & 0xffffff;
	usd.sd.sd_hibase = (base >> 24) & 0xff;
	usd.sd.sd_lolimit = 0xffff;
	usd.sd.sd_hilimit = 0xf;
	usd.sd.sd_type = SDT_MEMRWA;
	usd.sd.sd_dpl = SEL_UPL;
	usd.sd.sd_p = 1;
	usd.sd.sd_def32 = 1;
	usd.sd.sd_gran = 1;

	pcb = lwp_getpcb(l);
	kpreempt_disable();
	if (which == 'f') {
		memcpy(&pcb->pcb_fsd, &usd.sd,
		    sizeof(struct segment_descriptor));
		if (l == curlwp) {
			update_descriptor(&curcpu()->ci_gdt[GUFS_SEL], &usd);
		}
		tf->tf_fs = GSEL(GUFS_SEL, SEL_UPL);
	} else /* which == 'g' */ {
		memcpy(&pcb->pcb_gsd, &usd.sd,
		    sizeof(struct segment_descriptor));
		if (l == curlwp) {
			update_descriptor(&curcpu()->ci_gdt[GUGS_SEL], &usd);
#if defined(__x86_64__) && defined(XENPV)
			setusergs(GSEL(GUGS_SEL, SEL_UPL));
#endif
		}
		tf->tf_gs = GSEL(GUGS_SEL, SEL_UPL);
	}
	kpreempt_enable();
	return 0;
}

int
x86_set_sdbase(void *arg, char which, lwp_t *l, bool direct)
{
#ifdef i386
	return x86_set_sdbase32(arg, which, l, direct);
#else
	struct pcb *pcb;
	vaddr_t base;

	if (l->l_proc->p_flag & PK_32) {
		return x86_set_sdbase32(arg, which, l, direct);
	}

	if (direct) {
		base = (vaddr_t)arg;
	} else {
		int error = copyin(arg, &base, sizeof(base));
		if (error != 0)
			return error;
	}

	if (base >= VM_MAXUSER_ADDRESS)
		return EINVAL;

	pcb = lwp_getpcb(l);

	kpreempt_disable();
	switch (which) {
	case 'f':
		pcb->pcb_fs = base;
		if (l == curlwp)
			wrmsr(MSR_FSBASE, pcb->pcb_fs);
		break;
	case 'g':
		pcb->pcb_gs = base;
		if (l == curlwp)
			wrmsr(MSR_KERNELGSBASE, pcb->pcb_gs);
		break;
	default:
		panic("x86_set_sdbase");
	}
	kpreempt_enable();

	return 0;
#endif
}

static int
x86_get_sdbase32(void *arg, char which)
{
	struct segment_descriptor *sd;
	uint32_t base;

	switch (which) {
	case 'f':
		sd = (void *)&curpcb->pcb_fsd;
		break;
	case 'g':
		sd = (void *)&curpcb->pcb_gsd;
		break;
	default:
		panic("x86_get_sdbase32");
	}

	base = sd->sd_hibase << 24 | sd->sd_lobase;
	return copyout(&base, arg, sizeof(base));
}

int
x86_get_sdbase(void *arg, char which)
{
#ifdef i386
	return x86_get_sdbase32(arg, which);
#else
	vaddr_t base;
	struct pcb *pcb;

	if (curproc->p_flag & PK_32) {
		return x86_get_sdbase32(arg, which);
	}

	pcb = lwp_getpcb(curlwp);

	switch (which) {
	case 'f':
		base = pcb->pcb_fs;
		break;
	case 'g':
		base = pcb->pcb_gs;
		break;
	default:
		panic("x86_get_sdbase");
	}

	return copyout(&base, arg, sizeof(base));
#endif
}

int
sys_sysarch(struct lwp *l, const struct sys_sysarch_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int) op;
		syscallarg(void *) parms;
	} */
	int error = 0;

	switch (SCARG(uap, op)) {
	case X86_IOPL:
		error = x86_iopl(l, SCARG(uap, parms), retval);
		break;

#ifdef i386
	/*
	 * On amd64, this is done via netbsd32_sysarch.
	 */
	case X86_GET_LDT:
		error = x86_get_ldt(l, SCARG(uap, parms), retval);
		break;

	case X86_SET_LDT:
		error = x86_set_ldt(l, SCARG(uap, parms), retval);
		break;
#endif

	case X86_GET_IOPERM:
		error = x86_get_ioperm(l, SCARG(uap, parms), retval);
		break;

	case X86_SET_IOPERM:
		error = x86_set_ioperm(l, SCARG(uap, parms), retval);
		break;

	case X86_GET_MTRR:
		error = x86_get_mtrr(l, SCARG(uap, parms), retval);
		break;
	case X86_SET_MTRR:
		error = x86_set_mtrr(l, SCARG(uap, parms), retval);
		break;

	case X86_SET_FSBASE:
		error = x86_set_sdbase(SCARG(uap, parms), 'f', curlwp, false);
		break;

	case X86_SET_GSBASE:
		error = x86_set_sdbase(SCARG(uap, parms), 'g', curlwp, false);
		break;

	case X86_GET_FSBASE:
		error = x86_get_sdbase(SCARG(uap, parms), 'f');
		break;

	case X86_GET_GSBASE:
		error = x86_get_sdbase(SCARG(uap, parms), 'g');
		break;

	default:
		error = EINVAL;
		break;
	}
	return error;
}

int
cpu_lwp_setprivate(lwp_t *l, void *addr)
{

#ifdef __x86_64__
	if ((l->l_proc->p_flag & PK_32) == 0) {
		return x86_set_sdbase(addr, 'f', l, true);
	}
#endif
	return x86_set_sdbase(addr, 'g', l, true);
}
