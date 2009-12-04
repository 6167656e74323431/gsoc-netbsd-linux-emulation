/*	$NetBSD: pmap_bootstrap.c,v 1.19 2009/12/04 18:06:28 tsutsui Exp $	*/

/* 
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 *
 *	@(#)pmap_bootstrap.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: pmap_bootstrap.c,v 1.19 2009/12/04 18:06:28 tsutsui Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/msgbuf.h>

#include <machine/frame.h>
#include <machine/cpu.h>
#include <machine/vmparam.h>
#include <machine/pte.h>

#include <uvm/uvm_extern.h>

#define RELOC(v, t)	*((t*)((uintptr_t)&(v) + firstpa - KERNBASE))
#define RELOCPTR(v, t)	((t)((uintptr_t)RELOC((v), t) + firstpa - KERNBASE))

extern char *etext;
extern paddr_t avail_start, avail_end;

void	pmap_bootstrap(vm_offset_t, vm_offset_t);

/*
 * Special purpose kernel virtual addresses, used for mapping
 * physical pages for a variety of temporary or permanent purposes:
 *
 *	CADDR1, CADDR2:	pmap zero/copy operations
 *	vmmap:		/dev/mem, crash dumps, parity error checking
 *	msgbufp:	kernel message buffer
 */
void *CADDR1, *CADDR2;
char *vmmap;
void *msgbufaddr;

/*
 * Bootstrap the VM system.
 *
 * Called with MMU off so we must relocate all global references by `firstpa'
 * (don't call any functions here!)  `nextpa' is the first available physical
 * memory address.  Returns an updated first PA reflecting the memory we
 * have allocated.  MMU is still off when we return.
 *
 * XXX assumes sizeof(u_int) == sizeof(pt_entry_t)
 * XXX a PIC compiler would make this much easier.
 */
void
pmap_bootstrap(vm_offset_t nextpa, vm_offset_t firstpa)
{
	vm_offset_t kstpa, kptpa, kptmpa, lkptpa, lwp0upa;
	u_int nptpages, kstsize;
	st_entry_t protoste, *ste;
	pt_entry_t protopte, *pte, *epte;

	/*
	 * Calculate important physical addresses:
	 *
	 *	kstpa		kernel segment table	1 page (!040)
	 *						N pages (040)
	 *
	 *	kptpa		statically allocated
	 *			kernel PT pages		Sysptsize+ pages
	 *
	 * [ Sysptsize is the number of pages of PT, IIOMAPSIZE and
	 *   EIOMAPSIZE are the number of PTEs, hence we need to round
	 *   the total to a page boundary with IO maps at the end. ]
	 *
	 *	kptmpa		kernel PT map		1 page
	 *
	 *	lkptpa		last kernel PT page	1 page
	 *
	 *	lwp0upa		lwp 0 u-area		UPAGES pages
	 *
	 * The KVA corresponding to any of these PAs is:
	 *	(PA - firstpa + KERNBASE).
	 */
	if (RELOC(mmutype, int) == MMU_68040)
		kstsize = MAXKL2SIZE / (NPTEPG/SG4_LEV2SIZE);
	else
		kstsize = 1;
	kstpa = nextpa;
	nextpa += kstsize * PAGE_SIZE;
	kptmpa = nextpa;
	nextpa += PAGE_SIZE;
	lkptpa = nextpa;
	nextpa += PAGE_SIZE;
	lwp0upa = nextpa;
	nextpa += USPACE;
	kptpa = nextpa;
	nptpages = RELOC(Sysptsize, int);
	nextpa += nptpages * PAGE_SIZE;

	/*
	 * Initialize segment table and kernel page table map.
	 *
	 * On 68030s and earlier MMUs the two are identical except for
	 * the valid bits so both are initialized with essentially the
	 * same values.  On the 68040, which has a mandatory 3-level
	 * structure, the segment table holds the level 1 table and part
	 * (or all) of the level 2 table and hence is considerably
	 * different.  Here the first level consists of 128 descriptors
	 * (512 bytes) each mapping 32mb of address space.  Each of these
	 * points to blocks of 128 second level descriptors (512 bytes)
	 * each mapping 256kb.  Note that there may be additional "segment
	 * table" pages depending on how large MAXKL2SIZE is.
	 *
	 * Portions of the last two segment of KVA space (0xFF800000 -
	 * 0xFFFFFFFF) are mapped for a couple of purposes.
	 * The first segment (0xFF800000 - 0xFFBFFFFF) is mapped
	 * for the kernel page tables.
	 *
	 * XXX: It looks this was copied from hp300 and not sure if
	 * XXX: last physical page mapping is really needed on this port.
	 * The very last page (0xFFFFF000) in the second segment is mapped
	 * to the last physical page of RAM to give us a region in which
	 * PA == VA.  We use the first part of this page for enabling
	 * and disabling mapping.  The last part of this page also contains
	 * info left by the boot ROM.
	 *
	 * XXX cramming two levels of mapping into the single "segment"
	 * table on the 68040 is intended as a temporary hack to get things
	 * working.  The 224mb of address space that this allows will most
	 * likely be insufficient in the future (at least for the kernel).
	 */
	if (RELOC(mmutype, int) == MMU_68040) {
		int num;

		/*
		 * First invalidate the entire "segment table" pages
		 * (levels 1 and 2 have the same "invalid" value).
		 */
		pte = (u_int *)kstpa;
		epte = &pte[kstsize * NPTEPG];
		while (pte < epte)
			*pte++ = SG_NV;

		/*
		 * Initialize level 2 descriptors (which immediately
		 * follow the level 1 table).  We need:
		 *	NPTEPG / SG4_LEV3SIZE
		 * level 2 descriptors to map each of the nptpages
		 * pages of PTEs.  Note that we set the "used" bit
		 * now to save the HW the expense of doing it.
		 */
		num = nptpages * (NPTEPG / SG4_LEV3SIZE);
		pte = &((u_int *)kstpa)[SG4_LEV1SIZE];
		epte = &pte[num];
		protoste = kptpa | SG_U | SG_RW | SG_V;
		while (pte < epte) {
			*pte++ = protoste;
			protoste += (SG4_LEV3SIZE * sizeof(st_entry_t));
		}

		/*
		 * Initialize level 1 descriptors.  We need:
		 *	roundup(num, SG4_LEV2SIZE) / SG4_LEV2SIZE
		 * level 1 descriptors to map the `num' level 2's.
		 */
		pte = (u_int *)kstpa;
		epte = &pte[roundup(num, SG4_LEV2SIZE) / SG4_LEV2SIZE];
		protoste = (u_int)&pte[SG4_LEV1SIZE] | SG_U | SG_RW | SG_V;
		while (pte < epte) {
			*pte++ = protoste;
			protoste += (SG4_LEV2SIZE * sizeof(st_entry_t));
		}

		/*
		 * Initialize the final level 1 descriptor to map the last
		 * block of level 2 descriptors.
		 */
		ste = &((u_int *)kstpa)[SG4_LEV1SIZE-1];
		pte = &((u_int *)kstpa)[kstsize*NPTEPG - SG4_LEV2SIZE];
		*ste = (u_int)pte | SG_U | SG_RW | SG_V;
		/*
		 * Now initialize the final portion of that block of
		 * descriptors to map kptmpa and the "last PT page".
		 */
		pte = &((u_int *)kstpa)[kstsize*NPTEPG - NPTEPG/SG4_LEV3SIZE*2];
		epte = &pte[NPTEPG/SG4_LEV3SIZE];
		protoste = kptmpa | SG_U | SG_RW | SG_V;
		while (pte < epte) {
			*pte++ = protoste;
			protoste += (SG4_LEV3SIZE * sizeof(st_entry_t));
		}
		epte = &pte[NPTEPG/SG4_LEV3SIZE];
		protoste = lkptpa | SG_U | SG_RW | SG_V;
		while (pte < epte) {
			*pte++ = protoste;
			protoste += (SG4_LEV3SIZE * sizeof(st_entry_t));
		}

		/*
		 * Initialize Sysptmap
		 */
		pte = (u_int *)kptmpa;
		epte = &pte[nptpages];
		protopte = kptpa | PG_RW | PG_CI | PG_V;
		while (pte < epte) {
			*pte++ = protopte;
			protopte += PAGE_SIZE;
		}

		/*
		 * Invalidate all but the last remaining entry.
		 */
		epte = &((u_int *)kptmpa)[NPTEPG-2];
		while (pte < epte) {
			*pte++ = PG_NV;
		}
		/*
		 * Initialize the last to point to kptmpa and the page
		 * table page allocated earlier.
		 */
		*pte = kptmpa | PG_RW | PG_CI | PG_V;
		pte++;
		*pte = lkptpa | PG_RW | PG_CI | PG_V;
	} else {
		/*
		 * Map the page table pages in both the HW segment table
		 * and the software Sysptmap.
		 */
		ste = (u_int *)kstpa;
		pte = (u_int *)kptmpa;
		epte = &pte[nptpages];
		protoste = kptpa | SG_RW | SG_V;
		protopte = kptpa | PG_RW | PG_CI | PG_V;
		while (pte < epte) {
			*ste++ = protoste;
			*pte++ = protopte;
			protoste += PAGE_SIZE;
			protopte += PAGE_SIZE;
		}
		/*
		 * Invalidate all but the last remaining entries in both.
		 */
		epte = &((u_int *)kptmpa)[NPTEPG-2];
		while (pte < epte) {
			*ste++ = SG_NV;
			*pte++ = PG_NV;
		}
		/*
		 * Initialize the last to point to kptmpa and the page
		 * table page allocated earlier.
		 */
		*ste = kptmpa | SG_RW | SG_V;
		*pte = kptmpa | PG_RW | PG_CI | PG_V;
		ste++;
		pte++;
		*ste = lkptpa | SG_RW | SG_V;
		*pte = lkptpa | PG_RW | PG_CI | PG_V;
	}
	/*
	 * Invalidate all but the final entry in the last kernel PT page
	 * (u-area PTEs will be validated later).  The final entry maps
	 * the last page of physical memory.
	 */
	pte = (u_int *)lkptpa;
	epte = &pte[NPTEPG];
	while (pte < epte)
		*pte++ = PG_NV;

	/*
	 * Initialize kernel page table.
	 * Start by invalidating the `nptpages' that we have allocated.
	 */
	pte = (u_int *)kptpa;
	epte = &pte[nptpages * NPTEPG];
	while (pte < epte)
		*pte++ = PG_NV;

	/*
	 * Validate PTEs for kernel text (RO).
	 */
	pte = &((u_int *)kptpa)[m68k_btop(KERNBASE)];
	epte = &((u_int *)kptpa)[m68k_btop(m68k_trunc_page(&etext))];
	protopte = firstpa | PG_RO | PG_V;
	while (pte < epte) {
		*pte++ = protopte;
		protopte += PAGE_SIZE;
	}
	/*
	 * Validate PTEs for kernel data/bss, dynamic data allocated
	 * by us so far (nextpa - firstpa bytes), and pages for lwp0
	 * u-area and page table allocated below (RW).
	 */
	epte = &((u_int *)kptpa)[m68k_btop(KERNBASE + nextpa - firstpa)];
	protopte = (protopte & ~PG_PROT) | PG_RW;
	/*
	 * Enable copy-back caching of data pages
	 */
	if (RELOC(mmutype, int) == MMU_68040)
		protopte |= PG_CCB;

	while (pte < epte) {
		*pte++ = protopte;
		protopte += PAGE_SIZE;
	}

	/*
	 * Calculate important exported kernel virtual addresses
	 */
	/*
	 * Sysseg: base of kernel segment table
	 */
	RELOC(Sysseg, st_entry_t *) =
		(st_entry_t *)(kstpa - firstpa + KERNBASE);
	/*
	 * Sysptmap: base of kernel page table map
	 */
	RELOC(Sysptmap, pt_entry_t *) =
		(pt_entry_t *)(kptmpa - firstpa + KERNBASE);
	/*
	 * Sysmap: kernel page table (as mapped through Sysptmap)
	 * Allocated at the end of KVA space.
	 */
	RELOC(Sysmap, pt_entry_t *) =
	    (pt_entry_t *)m68k_ptob((NPTEPG - 2) * NPTEPG);

	/*
	 * Setup u-area for lwp 0.
	 */
	/*
	 * Zero the u-area.
	 * NOTE: `pte' and `epte' aren't PTEs here.
	 */
	pte = (u_int *)lwp0upa;
	epte = (u_int *)(lwp0upa + USPACE);
	while (pte < epte)
		*pte++ = 0;
	/*
	 * Remember the u-area address so it can be loaded in the lwp0
	 * via uvm_lwp_setuarea() later in pmap_bootstrap_finalize().
	 */
	RELOC(lwp0uarea, vaddr_t) = lwp0upa - firstpa + KERNBASE;

	/*
	 * VM data structures are now initialized, set up data for
	 * the pmap module.
	 *
	 * Note about avail_end: msgbuf is initialized just after
	 * avail_end in machdep.c.  Since the last page is used
	 * for rebooting the system (code is copied there and
	 * excution continues from copied code before the MMU
	 * is disabled), the msgbuf will get trounced between
	 * reboots if it's placed in the last physical page.
	 * To work around this, we move avail_end back one more
	 * page so the msgbuf can be preserved.
	 */
	RELOC(avail_start, vm_offset_t) = nextpa;
	RELOC(avail_end, vm_offset_t) = firstpa
	  + m68k_ptob(RELOC(physmem, int))
	  - m68k_round_page(MSGBUFSIZE)
	  - PAGE_SIZE; /* if that start of last page??? */
	RELOC(virtual_avail, vm_offset_t) =
		KERNBASE + (nextpa - firstpa);
	RELOC(virtual_end, vm_offset_t) = VM_MAX_KERNEL_ADDRESS;

	/*
	 * Initialize protection array.
	 * XXX don't use a switch statement, it might produce an
	 * absolute "jmp" table.
	 */
	{
		u_int *kp;

		kp = &RELOC(protection_codes, u_int);
		kp[VM_PROT_NONE|VM_PROT_NONE|VM_PROT_NONE] = 0;
		kp[VM_PROT_READ|VM_PROT_NONE|VM_PROT_NONE] = PG_RO;
		kp[VM_PROT_READ|VM_PROT_NONE|VM_PROT_EXECUTE] = PG_RO;
		kp[VM_PROT_NONE|VM_PROT_NONE|VM_PROT_EXECUTE] = PG_RO;
		kp[VM_PROT_NONE|VM_PROT_WRITE|VM_PROT_NONE] = PG_RW;
		kp[VM_PROT_NONE|VM_PROT_WRITE|VM_PROT_EXECUTE] = PG_RW;
		kp[VM_PROT_READ|VM_PROT_WRITE|VM_PROT_NONE] = PG_RW;
		kp[VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE] = PG_RW;
	}

	/*
	 * Kernel page/segment table allocated above,
	 * just initialize pointers.
	 */
	{
		struct pmap *kpm;

		kpm = RELOCPTR(kernel_pmap_ptr, struct pmap *);

		kpm->pm_stab = RELOC(Sysseg, st_entry_t *);
		kpm->pm_ptab = RELOC(Sysmap, pt_entry_t *);
		simple_lock_init(&kpm->pm_lock);
		kpm->pm_count = 1;
		kpm->pm_stpa = (st_entry_t *)kstpa;
		/*
		 * For the 040 we also initialize the free level 2
		 * descriptor mask noting that we have used:
		 *	0:		level 1 table
		 *	1 to `num':	map page tables
		 *	MAXKL2SIZE-1:	maps kptmpa and last-page page table
		 */
		if (RELOC(mmutype, int) == MMU_68040) {
			int num;
			
			kpm->pm_stfree = ~l2tobm(0);
			num = roundup(nptpages * (NPTEPG / SG4_LEV3SIZE),
				      SG4_LEV2SIZE) / SG4_LEV2SIZE;
			while (num)
				kpm->pm_stfree &= ~l2tobm(num--);
			kpm->pm_stfree &= ~l2tobm(MAXKL2SIZE-1);
			for (num = MAXKL2SIZE;
			     num < sizeof(kpm->pm_stfree)*NBBY;
			     num++)
				kpm->pm_stfree &= ~l2tobm(num);
		}
	}

	/*
	 * Allocate some fixed, special purpose kernel virtual addresses
	 */
	{
		vm_offset_t va = RELOC(virtual_avail, vm_offset_t);

		RELOC(CADDR1, void *) = (void *)va;
		va += PAGE_SIZE;
		RELOC(CADDR2, void *) = (void *)va;
		va += PAGE_SIZE;
		RELOC(vmmap, void *) = (void *)va;
		va += PAGE_SIZE;
		RELOC(msgbufaddr, void *) = (void *)va;
		va += m68k_round_page(MSGBUFSIZE);
		RELOC(virtual_avail, vm_offset_t) = va;
	}
}
