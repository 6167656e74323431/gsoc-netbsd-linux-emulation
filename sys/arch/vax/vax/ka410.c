/*	$NetBSD: ka410.c,v 1.8 1998/05/17 19:00:56 ragge Exp $ */
/*
 * Copyright (c) 1996 Ludd, University of Lule}, Sweden.
 * All rights reserved.
 *
 * This code is derived from software contributed to Ludd by Bertram Barth.
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
 *	This product includes software developed at Ludd, University of 
 *	Lule}, Sweden and its contributors.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>

#include <machine/pte.h>
#include <machine/cpu.h>
#include <machine/mtpr.h>
#include <machine/sid.h>
#include <machine/pmap.h>
#include <machine/nexus.h>
#include <machine/uvax.h>
#include <machine/ka410.h>
#include <machine/clock.h>
#include <machine/vsbus.h>

static	void	ka410_conf __P((struct device*, struct device*, void*));
static	void	ka410_steal_pages __P((void));
static	void	ka410_memerr __P((void));
static	int	ka410_mchk __P((caddr_t));
static	void	ka410_halt __P((void));
static	void	ka410_reboot __P((int));

extern  short *clk_page;

static	struct uc_map ka410_map[] = {
	{ KA410_CFGTST,		KA410_CFGTST+1023,	1024,	0 },
	{ KA410_ROM_BASE,	KA410_ROM_END,	KA410_ROM_SIZE, 0 },
	{ (int)KA410_CPU_BASE,	KA410_CPU_END,	KA410_CPU_SIZE, 0 },
	{ KA410_NWA_BASE,	KA410_NWA_END,	KA410_NWA_SIZE, 0 },
	{ KA410_SER_BASE,	KA410_SER_END,	KA410_SER_SIZE, 0 },
	{ (int)KA410_WAT_BASE,	KA410_WAT_END,	KA410_WAT_SIZE, 0 },
#if 0
	{ KA410_SCS_BASE,	KA410_SCS_END,	KA410_SCS_SIZE, 0 },
#else
	{ 0x200C0000,		0x200C01FF,	0x200,		0 },
#endif
	{ KA410_LAN_BASE,	KA410_LAN_END,	KA410_LAN_SIZE, 0 },
	{ KA410_CUR_BASE,	KA410_CUR_END,	KA410_CUR_SIZE, 0 },
	{ KA410_DMA_BASE,	KA410_DMA_END,	KA410_DMA_SIZE, 0 },
	/*
	 * there's more to come, eg. framebuffers (mono + GPX)
	 */
	{0, 0, 0, 0},
};

/* 
 * Declaration of 410-specific calls.
 */
struct	cpu_dep ka410_calls = {
	ka410_steal_pages,
	no_nicr_clock,
	ka410_mchk,
	ka410_memerr, 
	ka410_conf,
	chip_clkread,
	chip_clkwrite,
	1,      /* ~VUPS */
	(void*)KA410_INTREQ,      /* Used by vaxstation */
	(void*)KA410_INTCLR,      /* Used by vaxstation */
	(void*)KA410_INTMSK,      /* Used by vaxstation */
	ka410_map,
	ka410_halt,
	ka410_reboot,
};


void
ka410_conf(parent, self, aux)
	struct	device *parent, *self;
	void	*aux;
{
	extern char cpu_model[];

	switch (vax_cputype) {
	case VAX_TYP_UV2:
		if (vax_confdata & 0x80)	/* MSB in CFGTST */
			strcpy(cpu_model,"MicroVAX 2000");
		else
			strcpy(cpu_model,"VAXstation 2000");
		break;

	case VAX_TYP_CVAX:
		/* if (((vax_siedata >> 8) & 0xff) == 2) */
		strcpy(cpu_model,"MicroVAX 3100 (KA41)");
		/* ka41_cache_enable(); */
	}

	printf(": %s\n", cpu_model);
}

void
ka410_memerr()
{
	printf("Memory err!\n");
}

int
ka410_mchk(addr)
	caddr_t addr;
{
	panic("Machine check");
	return 0;
}

void
ka410_steal_pages()
{
	extern	vm_offset_t avail_start, virtual_avail;
        extern  int clk_adrshift, clk_tweak;
	int	junk, parctl = 0;

	/* 
	 * SCB is already copied/initialized at addr avail_start
	 * by pmap_bootstrap(), but it's not yet mapped. Thus we use
	 * the MAPPHYS() macro to reserve these two pages and to
	 * perform the mapping. The mapped address is assigned to junk.
	 */
	MAPPHYS(junk, 2, VM_PROT_READ|VM_PROT_WRITE);

	/*
	 * Setup parameters necessary to read time from clock chip.
	 */
	clk_adrshift = 1;       /* Addressed at long's... */
	clk_tweak = 2;          /* ...and shift two */
	MAPVIRT(clk_page, 1);
	pmap_map((vm_offset_t)clk_page, (vm_offset_t)KA410_WAT_BASE,
	    (vm_offset_t)KA410_WAT_BASE + NBPG, VM_PROT_READ|VM_PROT_WRITE);

	/* LANCE CSR & DMA memory */
	MAPVIRT(lance_csr, 1);
	pmap_map((vm_offset_t)lance_csr, (vm_offset_t)NI_BASE,
	    (vm_offset_t)NI_BASE + NBPG, VM_PROT_READ|VM_PROT_WRITE);

	MAPVIRT(vs_cpu, 1);
	pmap_map((vm_offset_t)vs_cpu, (vm_offset_t)VS_REGS,
	    (vm_offset_t)VS_REGS + NBPG, VM_PROT_READ|VM_PROT_WRITE);

	MAPVIRT(dz_regs, 2);
	pmap_map((vm_offset_t)dz_regs, (vm_offset_t)DZ_CSR,
	    (vm_offset_t)DZ_CSR + NBPG, VM_PROT_READ|VM_PROT_WRITE);

	MAPVIRT(lance_addr, 1);
	pmap_map((vm_offset_t)lance_addr, (vm_offset_t)NI_ADDR,
	    (vm_offset_t)NI_ADDR + NBPG, VM_PROT_READ|VM_PROT_WRITE);

	MAPPHYS(le_iomem, (NI_IOSIZE/NBPG), VM_PROT_READ|VM_PROT_WRITE);

	if (((int)le_iomem & ~KERNBASE) > 0xffffff)
		parctl = PARCTL_DMA;
	/*
	 * VAXstation 2000 and MicroVAX 2000: 
	 * since there's no bus, we have to map in anything which 
	 * could be neccessary/used/interesting...
	 * 
	 * MAPVIRT(ptr,count) reserves a virtual area with the requested size
	 *			and initializes ptr to point at this location
	 * pmap_map(ptr,...)  inserts a pair of virtual/physical addresses
	 *			into the system maptable (Sysmap)
	 */
	uvax_fillmap();

	/*
	 * Clear restart and boot in progress flags
	 * in the CPMBX. (ie. clear bits 4 and 5)
	 */
	KA410_WAT_BASE->cpmbx = (KA410_WAT_BASE->cpmbx & ~0x30);

	/*
	 * Enable memory parity error detection and clear error bits.
	 */
        switch (vax_cputype) {
        case VAX_TYP_UV2:
		KA410_CPU_BASE->ka410_mser = 1;
                break;

        case VAX_TYP_CVAX:
		((struct vs_cpu *)VS_REGS)->vc_parctl =
		    parctl | PARCTL_CPEN | PARCTL_DPEN ;
		break;
        }
}

static void
ka410_halt()
{
	asm("movl $0xc, (%0)"::"r"((int)clk_page + 0x38)); /* Don't ask */
	asm("halt");
}

static void
ka410_reboot(arg)
	int arg;
{
	asm("movl $0xc, (%0)"::"r"((int)clk_page + 0x38)); /* Don't ask */
	asm("halt");
}
