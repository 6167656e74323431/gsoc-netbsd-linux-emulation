/*	$NetBSD: obio.c,v 1.42 1998/03/29 22:05:05 pk Exp $	*/

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Paul Kranenburg.
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


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/malloc.h>

#ifdef DEBUG
#include <sys/proc.h>
#include <sys/syslog.h>
#endif

#include <vm/vm.h>

#include <machine/bus.h>
#include <sparc/dev/sbusvar.h>
#include <machine/autoconf.h>
#include <machine/pmap.h>
#include <machine/oldmon.h>
#include <machine/cpu.h>
#include <machine/ctlreg.h>
#include <sparc/sparc/asm.h>
#include <sparc/sparc/vaddrs.h>
#include <sparc/sparc/cpuvar.h>

struct obio4_softc {
	struct device	sc_dev;		/* base device */
	bus_space_tag_t	sc_bustag;	/* parent bus tag */
	bus_dma_tag_t	sc_dmatag;	/* parent bus dma tag */
};

union obio_softc {
	struct	device sc_dev;		/* base device */
	struct	obio4_softc sc_obio;	/* sun4 obio */
	struct	sbus_softc sc_sbus;	/* sun4m obio is another sbus slot */
};


/* autoconfiguration driver */
static	int obiomatch  __P((struct device *, struct cfdata *, void *));
static	void obioattach __P((struct device *, struct device *, void *));

struct cfattach obio_ca = {
	sizeof(union obio_softc), obiomatch, obioattach
};

#if defined(SUN4)
static	int obioprint  __P((void *, const char *));
static	int obiosearch   __P((struct device *, struct cfdata *, void *));
static	int obio_bus_mmap __P((void *, bus_type_t, bus_addr_t, int));
static	int _obio_bus_map __P((void *, bus_type_t, bus_addr_t, bus_size_t,
			       int, vm_offset_t, bus_space_handle_t *));

static struct sparc_bus_space_tag obio_space_tag = {
	NULL,				/* cookie */
	_obio_bus_map,			/* bus_space_map */ 
	NULL,				/* bus_space_unmap */
	NULL,				/* bus_space_subregion */
	NULL,				/* bus_space_barrier */ 
	obio_bus_mmap,			/* bus_space_mmap */ 
	NULL				/* bus_intr_establish */
}; 
#endif

/*
 * Translate obio `interrupts' property value to processor IPL (see sbus.c)
 * Apparently, the `interrupts' property on obio devices is just
 * the processor IPL.
 */
static int intr_obio2ipl[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

int
obiomatch(parent, cf, aux)
	struct device *parent;
	struct cfdata *cf;
	void *aux;
{
	struct mainbus_attach_args *ma = aux;

	return (strcmp(cf->cf_driver->cd_name, ma->ma_name) == 0);
}

void
obioattach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	struct mainbus_attach_args *ma = aux;

	/*
	 * There is only one obio bus
	 */
	if (self->dv_unit > 0) {
		printf(" unsupported\n");
		return;
	}
	printf("\n");

	if (CPU_ISSUN4) {
#if defined(SUN4)
		struct obio4_softc *sc = &((union obio_softc *)self)->sc_obio;

		sc->sc_bustag = ma->ma_bustag;
		sc->sc_dmatag = ma->ma_dmatag;

		obio_space_tag.cookie = sc;

		/* Propagate assorted parent functions */
		obio_space_tag.sparc_intr_establish =
			ma->ma_bustag->sparc_intr_establish;
		obio_space_tag.sparc_bus_unmap =
			ma->ma_bustag->sparc_bus_unmap;

		(void)config_search(obiosearch, self, aux);
#endif
		return;
	} else if (CPU_ISSUN4M) {
		/*
		 * Attach the on-board I/O bus at on a sun4m.
		 * In this case we treat the obio bus as another sbus slot.
		 */
		struct sbus_softc *sc = &((union obio_softc *)self)->sc_sbus;

		static const char *const special4m[] = {
			/* find these first */
			"eeprom",
			"counter",
#if 0 /* Not all sun4m's have an `auxio' */
			"auxio",
#endif
			"",
			/* place device to ignore here */
			"interrupt",
			NULL
		};

		sc->sc_bustag = ma->ma_bustag;
		sc->sc_dmatag = ma->ma_dmatag;
		sc->sc_intr2ipl = intr_obio2ipl;

		sbus_attach(sc, "obio", ma->ma_node, ma->ma_bp, special4m);
	} else {
		printf("obio on this machine?\n");
	}
}

#if defined(SUN4)
int
obioprint(args, busname)
	void *args;
	const char *busname;
{
	union obio_attach_args *uoba = args;
	struct obio4_attach_args *oba = &uoba->uoba_oba4;

	printf(" addr 0x%lx", (long)oba->oba_paddr);
	if (oba->oba_pri != -1)
		printf(" level %d", oba->oba_pri);

	return (UNCONF);
}

int
_obio_bus_map(cookie, btype, paddr, size, flags, vaddr, hp)
	void	*cookie;
	bus_type_t btype;
	bus_addr_t paddr;
	bus_size_t size;
	int	flags;
	vm_offset_t vaddr;
	bus_space_handle_t *hp;
{
	struct obio4_softc *sc = cookie;

	if ((flags & OBIO_BUS_MAP_USE_ROM) != 0 &&
	     obio_find_rom_map(paddr, PMAP_OBIO, size, hp) == 0)
		return (0);

	return (bus_space_map2(sc->sc_bustag, PMAP_OBIO, paddr,
				size, flags, vaddr, hp));
}

int
obio_bus_mmap(cookie, btype, paddr, flags)
	void *cookie;
	bus_type_t btype;
	bus_addr_t paddr;
	int flags;
{
	struct obio4_softc *sc = cookie;

	return (bus_space_mmap(sc->sc_bustag, PMAP_OBIO, paddr, flags));
}

int
obiosearch(parent, cf, aux)
	struct device *parent;
	struct cfdata *cf;
	void *aux;
{
	struct mainbus_attach_args *ma = aux;
	union obio_attach_args uoba;
	struct obio4_attach_args *oba = &uoba.uoba_oba4;
	struct bootpath *bp;


	/*
	 * Avoid sun4m entries which don't have valid PAs.
	 * no point in even probing them. 
	 */
	if (cf->cf_loc[0] == -1)
		return (0);

	/*
	 * On the 4/100 obio addresses must be mapped at
	 * 0x0YYYYYYY, but alias higher up (we avoid the
	 * alias condition because it causes pmap difficulties)
	 * XXX: We also assume that 4/[23]00 obio addresses
	 * must be 0xZYYYYYYY, where (Z != 0)
	 */
	if (cpuinfo.cpu_type == CPUTYP_4_100 && (cf->cf_loc[0] & 0xf0000000))
		return (0);
	if (cpuinfo.cpu_type != CPUTYP_4_100 && !(cf->cf_loc[0] & 0xf0000000))
		return (0);

	uoba.uoba_isobio4 = 1;
	oba->oba_bustag = &obio_space_tag;
	oba->oba_dmatag = ma->ma_dmatag;
	oba->oba_paddr = cf->cf_loc[0];
	oba->oba_pri = cf->cf_loc[1];

	bp = ma->ma_bp;
	if (bp != NULL && strcmp(bp->name, "obio") == 0)
		oba->oba_bp = bp + 1;
	else
		oba->oba_bp = NULL;

	if ((*cf->cf_attach->ca_match)(parent, cf, &uoba) == 0)
		return (0);

	config_attach(parent, cf, &uoba, obioprint);
	return (1);
}


/*
 * If we can find a mapping that was established by the rom, use it.
 * Else, create a new mapping.
 */
int
obio_find_rom_map(pa, iospace, len, hp)
	bus_addr_t	pa;
	bus_type_t	iospace;
	int		len;
	bus_space_handle_t *hp;
{
#define	getpte(va)		lda(va, ASI_PTE)

	u_long	pf;
	int	pgtype;
	u_long	va, pte;

	if (len > NBPG)
		return (EINVAL);

	pf = pa >> PGSHIFT;
	pgtype = PMAP_T2PTE_4(iospace);

	for (va = OLDMON_STARTVADDR; va < OLDMON_ENDVADDR; va += NBPG) {
		pte = getpte(va);
		if ((pte & PG_V) == 0 || (pte & PG_TYPE) != pgtype ||
		    (pte & PG_PFNUM) != pf)
			continue;

		/*
		 * Found entry in PROM's pagetable
		 * note: preserve page offset
		 */
		*hp = (bus_space_handle_t)(va | ((u_long)pa & PGOFSET));
		return (0);
	}

	return (ENOENT);
}
#endif /* SUN4 */
