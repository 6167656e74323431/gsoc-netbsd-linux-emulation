/*	$NetBSD: hydra.c,v 1.7 2002/10/05 23:30:03 bjh21 Exp $	*/

/*-
 * Copyright (c) 2002 Ben Harris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

__KERNEL_RCSID(0, "$NetBSD: hydra.c,v 1.7 2002/10/05 23:30:03 bjh21 Exp $");

#include <sys/device.h>
#include <sys/systm.h>

#include <uvm/uvm_extern.h>
#include <uvm/uvm_pglist.h>

#include <arch/arm/mainbus/mainbus.h>
#include <arch/acorn32/acorn32/hydrareg.h>
#include <arch/acorn32/acorn32/hydravar.h>

#include "locators.h"

struct hydra_softc {
	struct device		sc_dev;
	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;
	paddr_t			sc_bootpage_pa;
	vaddr_t			sc_bootpage_va;
	void			*sc_shutdownhook;
};

struct hydra_attach_args {
	int ha_slave;
};

static int hydra_match(struct device *, struct cfdata *, void *);
static void hydra_attach(struct device *, struct device *, void *);
static int hydra_probe_slave(struct hydra_softc *, int);
static int hydra_print(void *, char const *);
static int hydra_submatch(struct device *, struct cfdata *, void *);
static void hydra_shutdown(void *);

static void hydra_reset(struct hydra_softc *);

static int cpu_hydra_match(struct device *, struct cfdata *, void *);
static void cpu_hydra_attach(struct device *, struct device *, void *);
static void cpu_hydra_hatch(void);

CFATTACH_DECL(hydra, sizeof(struct hydra_softc),
    hydra_match, hydra_attach, NULL, NULL);
CFATTACH_DECL(cpu_hydra, sizeof(struct device),
    cpu_hydra_match, cpu_hydra_attach, NULL, NULL);

extern char const hydra_probecode[], hydra_eprobecode[];
extern char const hydra_hatchcode[], hydra_ehatchcode[];

static struct hydra_softc *the_hydra;

static int
hydra_match(struct device *parent, struct cfdata *cf, void *aux)
{
	struct mainbus_attach_args *mba = aux;
	bus_space_tag_t iot;
	bus_space_handle_t ioh;

	/*
	 * Probing for the Hydra is slightly tricky, since if there's
	 * no Hydra, the data we read seem fairly random.  Happily,
	 * nothing else uses its addresses, so we can be as invasive
	 * as we like.
	 */

	iot = mba->mb_iot;
	if (bus_space_map(iot, HYDRA_PHYS_BASE, HYDRA_PHYS_SIZE, 0, &ioh) != 0)
		return 0;

	/* Make sure all slaves are halted. */
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 0xf);
	/* Check that we appear to be the master. */
	if (bus_space_read_1(iot, ioh, HYDRA_ID_STATUS) & HYDRA_ID_ISSLAVE)
		goto fail;
	/* Check that the MMU enable bits behave as expected. */
	bus_space_write_1(iot, ioh, HYDRA_MMU_CLR, 0xf);
	if (bus_space_read_1(iot, ioh, HYDRA_MMU_STATUS) != 0x0)
		goto fail;
	bus_space_write_1(iot, ioh, HYDRA_MMU_SET, 0x5);
	if (bus_space_read_1(iot, ioh, HYDRA_MMU_STATUS) != 0x5)
		goto fail;
	bus_space_write_1(iot, ioh, HYDRA_MMU_SET, 0xa);
	if (bus_space_read_1(iot, ioh, HYDRA_MMU_STATUS) != 0xf)
		goto fail;
	bus_space_write_1(iot, ioh, HYDRA_MMU_CLR, 0x5);
	if (bus_space_read_1(iot, ioh, HYDRA_MMU_STATUS) != 0xa)
		goto fail;
	bus_space_write_1(iot, ioh, HYDRA_MMU_CLR, 0xa);
	if (bus_space_read_1(iot, ioh, HYDRA_MMU_STATUS) != 0x0)
		goto fail;
	bus_space_unmap(iot, ioh, HYDRA_PHYS_SIZE);
	return 1;

fail:
	bus_space_unmap(iot, ioh, HYDRA_PHYS_SIZE);
	return 0;	
}

static void
hydra_attach(struct device *parent, struct device *self, void *aux)
{
	struct hydra_softc *sc = (void *)self;
	struct mainbus_attach_args *mba = aux;
	int i, vers;
	struct hydra_attach_args ha;
	struct pglist bootpglist;
	bus_space_tag_t iot;
	bus_space_handle_t ioh;

	if (the_hydra == NULL)
		the_hydra = sc;

	sc->sc_iot = mba->mb_iot;
	if (bus_space_map(sc->sc_iot, HYDRA_PHYS_BASE, HYDRA_PHYS_SIZE, 0,
		&sc->sc_ioh) != 0) {
		printf(": cannot map\n");
		return;
	}
	iot = sc->sc_iot;
	ioh = sc->sc_ioh;

	/*
	 * The Hydra has special hardware to allow a slave processor
	 * to see something other than ROM at physical address 0 when
	 * it starts.  This something has to have a physical address
	 * on a 2MB boundary.
	 */
	TAILQ_INIT(&bootpglist);
	if (uvm_pglistalloc(PAGE_SIZE, 0x00000000, 0x1fffffff, 0x00200000, 0,
		&bootpglist, 1, 1) != 0) {
		printf(": Can't allocate bootstrap memory.\n");
		return;
	}
	KASSERT(!TAILQ_EMPTY(&bootpglist));
	sc->sc_bootpage_pa = TAILQ_FIRST(&bootpglist)->phys_addr;
	sc->sc_bootpage_va = uvm_km_valloc(kernel_map, PAGE_SIZE);
	if (sc->sc_bootpage_va == 0) {
		uvm_pglistfree(&bootpglist);
		printf(": Can't allocate bootstrap memory.\n");
		return;
	}
	pmap_enter(pmap_kernel(), sc->sc_bootpage_va, sc->sc_bootpage_pa,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE | PMAP_WIRED);
	pmap_update(pmap_kernel());

	vers = bus_space_read_1(iot, ioh, HYDRA_HARDWAREVER) & 0xf;
	printf(": hardware version %d", vers);

	hydra_reset(sc);

	/* Ensure that the Hydra gets shut down properly. */
	sc->sc_shutdownhook = shutdownhook_establish(hydra_shutdown, sc);

	/* Initialise MMU */
	bus_space_write_1(iot, ioh, HYDRA_MMU_LSN, sc->sc_bootpage_pa >> 21);
	bus_space_write_1(iot, ioh, HYDRA_MMU_MSN, sc->sc_bootpage_pa >> 25);

	printf("\n");

	for (i = 0; i < HYDRA_NSLAVES; i++) {
		if (hydra_probe_slave(sc, i)) {
			ha.ha_slave = i;
			config_found_sm(self, &ha, hydra_print,
			    hydra_submatch);
		}
	}
}

static int
hydra_probe_slave(struct hydra_softc *sc, int slave)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int i, ret;

	memcpy((caddr_t)sc->sc_bootpage_va, hydra_probecode,
	    hydra_eprobecode - hydra_probecode);
	bus_space_write_1(iot, ioh, HYDRA_MMU_SET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_RESET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_HALT_CLR, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_RESET, 0);
	ret = 0;
	for (i = 0; i < 1000; i++) {
		if ((bus_space_read_1(iot, ioh, HYDRA_HALT_STATUS) &
			(1 << slave)) != 0) {
			ret = 1;
			break;
		}
	}
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_MMU_CLR, 1 << slave);
	return ret;
}

static int
hydra_print(void *aux, char const *pnp)
{
	struct hydra_attach_args *ha = aux;

	if (pnp)
		printf("cpu at %s", pnp);
	printf(" slave %d", ha->ha_slave);
	return UNCONF;
}

static int
hydra_submatch(struct device *parent, struct cfdata *cf, void *aux)
{
	struct hydra_attach_args *ha = aux;

	if (cf->cf_loc[HYDRACF_SLAVE] == HYDRACF_SLAVE_DEFAULT ||
	    cf->cf_loc[HYDRACF_SLAVE] == ha->ha_slave)
		return 1;
	return 0;
}

static void
hydra_shutdown(void *arg)
{
	struct hydra_softc *sc = arg;

	hydra_reset(sc);
}

/*
 * hydra_reset: Put the Hydra back into the state it's in after a hard reset.
 * Must be run on the master CPU.
 */
static void
hydra_reset(struct hydra_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;

	KASSERT((bus_space_read_1(iot, ioh, HYDRA_ID_STATUS) &
	    HYDRA_ID_ISSLAVE) == 0);
	/* Halt all slaves */
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 0xf);
	bus_space_write_1(iot, ioh, HYDRA_RESET, 0x0);
	/* Clear IPFIQs to master */
	bus_space_write_1(iot, ioh, HYDRA_FIQ_CLR, 0xf);
	/* ... and to all slaves */
	bus_space_write_1(iot, ioh, HYDRA_FORCEFIQ_CLR, 0xf);
	/* Ditto IPIRQs */
	bus_space_write_1(iot, ioh, HYDRA_IRQ_CLR, 0xf);
	bus_space_write_1(iot, ioh, HYDRA_FORCEIRQ_CLR, 0xf);
	/* Initialise MMU */
	bus_space_write_1(iot, ioh, HYDRA_MMU_LSN, 0);
	bus_space_write_1(iot, ioh, HYDRA_MMU_MSN, 0);
	bus_space_write_1(iot, ioh, HYDRA_MMU_CLR, 0xf);
}

static int
cpu_hydra_match(struct device *parent, struct cfdata *cf, void *aux)
{

	/* If there's anything there, it's a CPU. */
	return 1;
}

static void
cpu_hydra_attach(struct device *parent, struct device *self, void *aux)
{
	struct hydra_softc *sc = (void *)parent;
	struct hydra_attach_args *ha = aux;
	int slave = ha->ha_slave;
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int i, ret, error;
	vaddr_t uaddr;
	struct hydraboot_vars *hb;

	/*
	 * Generate a kernel stack and PCB (in essence, a u-area) for the
	 * new CPU.
	 */
	uaddr = uvm_uarea_alloc();
	error = uvm_fault_wire(kernel_map, uaddr, uaddr + USPACE,
	    VM_FAULT_WIRE, VM_PROT_READ | VM_PROT_WRITE);
	if (error)
		panic("cpu_hydra_attach: uvm_fault_wire failed: %d", error);

	/* Copy hatch code to boot page, and set up arguments */
	memcpy((caddr_t)sc->sc_bootpage_va, hydra_hatchcode,
	    hydra_ehatchcode - hydra_hatchcode);
	KASSERT(hydra_ehatchcode - hydra_hatchcode <= HYDRABOOT_VARS);
	hb = (struct hydraboot_vars *)(sc->sc_bootpage_va + HYDRABOOT_VARS);
	hb->hb_ttb = (paddr_t)curproc->p_addr->u_pcb.pcb_pagedir;
	hb->hb_bootpage_pa = sc->sc_bootpage_pa;
	hb->hb_sp = uaddr + USPACE;
	hb->hb_entry = &cpu_hydra_hatch;

	cpu_drain_writebuf();

	bus_space_write_1(iot, ioh, HYDRA_MMU_SET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_RESET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_HALT_CLR, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_RESET, 0);
	ret = 0;
	for (i = 0; i < 100000; i++) {
		if ((bus_space_read_1(iot, ioh, HYDRA_HALT_STATUS) &
			(1 << slave)) != 0) {
			ret = 1;
			break;
		}
	}
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 1 << slave);
	bus_space_write_1(iot, ioh, HYDRA_MMU_CLR, 1 << slave);

	cpu_dcache_inv_range((vaddr_t)hb, sizeof(*hb));

	if (ret == 0) {
		printf(": failed to spin up\n");
		return;
	}
	printf("\n");
}

static void
cpu_hydra_hatch(void)
{
	struct hydra_softc *sc = the_hydra;
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int slave;

	slave = bus_space_read_1(iot, ioh, HYDRA_ID_STATUS) & 0x3;
	printf(": Number %d is alive!", slave);
	bus_space_write_1(iot, ioh, HYDRA_HALT_SET, 1 << slave);
	/* We only get here if someone resumes us. */
	for (;;)
		continue;
}

#ifdef MULTIPROCESSOR
void
cpu_boot_secondary_processors(void)
{

	/* Do nothing for now. */
}

cpuid_t
cpu_number(void)
{

	return 0;
}

extern struct cpu_info cpu_info_store;

struct cpu_info *
curcpu(void)
{

	return &cpu_info_store;
}
#endif
