/* $NetBSD: dwlpx_dma.c,v 1.8 1998/05/07 20:09:37 thorpej Exp $ */

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPEDWLPxL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */

__KERNEL_RCSID(0, "$NetBSD: dwlpx_dma.c,v 1.8 1998/05/07 20:09:37 thorpej Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <vm/vm.h>

#define _ALPHA_BUS_DMA_PRIVATE
#include <machine/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <alpha/tlsb/tlsbreg.h>
#include <alpha/tlsb/kftxxvar.h>
#include <alpha/tlsb/kftxxreg.h>
#include <alpha/pci/dwlpxreg.h>
#include <alpha/pci/dwlpxvar.h>
#include <alpha/pci/pci_kn8ae.h>

bus_dma_tag_t dwlpx_dma_get_tag __P((bus_dma_tag_t, alpha_bus_t));

int	dwlpx_bus_dmamap_create_sgmap __P((bus_dma_tag_t, bus_size_t, int,
	    bus_size_t, bus_size_t, int, bus_dmamap_t *));

void	dwlpx_bus_dmamap_destroy_sgmap __P((bus_dma_tag_t, bus_dmamap_t));

int	dwlpx_bus_dmamap_load_sgmap __P((bus_dma_tag_t, bus_dmamap_t, void *,
	    bus_size_t, struct proc *, int));

int	dwlpx_bus_dmamap_load_mbuf_sgmap __P((bus_dma_tag_t, bus_dmamap_t,
	    struct mbuf *, int));

int	dwlpx_bus_dmamap_load_uio_sgmap __P((bus_dma_tag_t, bus_dmamap_t,
	    struct uio *, int));

int	dwlpx_bus_dmamap_load_raw_sgmap __P((bus_dma_tag_t, bus_dmamap_t,
	    bus_dma_segment_t *, int, bus_size_t, int));

void	dwlpx_bus_dmamap_unload_sgmap __P((bus_dma_tag_t, bus_dmamap_t));

#define	DWLPx_DIRECT_MAPPED_BASE	0x80000000
#define	DWLPx_SG_MAPPED_BASE		0x10000000

void
dwlpx_dma_init(ccp)
	struct dwlpx_config *ccp;
{
	char *exname;
	bus_dma_tag_t t;
	u_int32_t *page_table;
	int i, lim, wmask;

	/*
	 * Initialize the DMA tag used for direct-mapped DMA.
	 */
	t = &ccp->cc_dmat_direct;
	t->_cookie = ccp;
	t->_wbase = DWLPx_DIRECT_MAPPED_BASE;
	t->_get_tag = dwlpx_dma_get_tag;
	t->_dmamap_create = _bus_dmamap_create;
	t->_dmamap_destroy = _bus_dmamap_destroy;
	t->_dmamap_load = _bus_dmamap_load_direct;
	t->_dmamap_load_mbuf = _bus_dmamap_load_mbuf_direct;
	t->_dmamap_load_uio = _bus_dmamap_load_uio_direct;
	t->_dmamap_load_raw = _bus_dmamap_load_raw_direct;
	t->_dmamap_unload = _bus_dmamap_unload;
	t->_dmamap_sync = _bus_dmamap_sync;

	t->_dmamem_alloc = _bus_dmamem_alloc;
	t->_dmamem_free = _bus_dmamem_free;
	t->_dmamem_map = _bus_dmamem_map;
	t->_dmamem_unmap = _bus_dmamem_unmap;
	t->_dmamem_mmap = _bus_dmamem_mmap;

	/*
	 * Initialize the DMA tag used for sgmap-mapped DMA.
	 */
	t = &ccp->cc_dmat_sgmap;
	t->_cookie = ccp;
	t->_wbase = DWLPx_SG_MAPPED_BASE;
	t->_get_tag = dwlpx_dma_get_tag;
	t->_dmamap_create = dwlpx_bus_dmamap_create_sgmap;
	t->_dmamap_destroy = dwlpx_bus_dmamap_destroy_sgmap;
	t->_dmamap_load = dwlpx_bus_dmamap_load_sgmap;
	t->_dmamap_load_mbuf = dwlpx_bus_dmamap_load_mbuf_sgmap;
	t->_dmamap_load_uio = dwlpx_bus_dmamap_load_uio_sgmap;
	t->_dmamap_load_raw = dwlpx_bus_dmamap_load_raw_sgmap;
	t->_dmamap_unload = dwlpx_bus_dmamap_unload_sgmap;
	t->_dmamap_sync = _bus_dmamap_sync;

	t->_dmamem_alloc = _bus_dmamem_alloc;
	t->_dmamem_free = _bus_dmamem_free;
	t->_dmamem_map = _bus_dmamem_map;
	t->_dmamem_unmap = _bus_dmamem_unmap;
	t->_dmamem_mmap = _bus_dmamem_mmap;

	/*
	 * A few notes about SGMAP-mapped DMA on the DWLPx:
	 *
	 * The DWLPx has PCIA-resident SRAM that is used for
	 * the SGMAP page table; there is no TLB.  The DWLPA
	 * has room for 32K entries, yielding a total of 256M
	 * of sgva space.  The DWLPB has 32K entries or 128K
	 * entries, depending on TBIT, yielding either 256M or
	 * 1G of sgva space.
	 *
	 * This sgva space must be shared across all windows
	 * that wish to use SGMAP-mapped DMA; make sure to
	 * adjust the "sgvabase" argument to alpha_sgmap_init()
	 * accordingly if you create more than one SGMAP-mapped
	 * window.  Note that sgvabase != window base.  The former
	 * is used to compute indexes into the page table only.
	 *
	 * In the current implementation the first window is a
	 * 2G window direct-mapped mapped at 2G and the second
	 * window is disabled and the third window is a 256M
	 * or 1GB scatter/gather map at 1GB.
	 */

	/*
	 * Initialize the page table.
	 */
	page_table =
	    (u_int32_t *)ALPHA_PHYS_TO_K0SEG(PCIA_SGMAP_PT + ccp->cc_sysbase);
	if (ccp->cc_sc->dwlpx_sgmapsz == DWLPX_SG128K) {
		lim = 128 * 1024;
		wmask = PCIA_WMASK_1G;
	} else {
		lim = 32 * 1024;
		wmask = PCIA_WMASK_256M;
	}
	for (i = 0; i < lim; i++)
		page_table[i * SGMAP_PTE_SPACING] = 0;
	alpha_mb();

	/*
	 * Initialize the SGMAP for window C:
	 *
	 *	Size: 256M or 1GB
	 *	Window base: 1GB
	 *	SGVA base: 0
	 */
	exname = malloc(16, M_DEVBUF, M_NOWAIT);
	if (exname == NULL)
		panic("dwlpx_dma_init");
	sprintf(exname, "%s_sgmap_a", ccp->cc_sc->dwlpx_dev.dv_xname);
	alpha_sgmap_init(t, &ccp->cc_sgmap, exname, DWLPx_SG_MAPPED_BASE,
	    0, lim * NBPG, sizeof(u_int32_t), (void *)page_table, 0);

	/*
	 * Set up DMA windows for this DWLPx.
	 *
	 * Do this even for all HPCs- even for the nonexistent
	 * one on hose zero of a KFTIA.
	 */
	for (i = 0; i < NHPC; i++) {
		REGVAL(PCIA_WMASK_A(i) + ccp->cc_sysbase) = PCIA_WMASK_2G;
		REGVAL(PCIA_TBASE_A(i) + ccp->cc_sysbase) = 0;
		REGVAL(PCIA_WBASE_A(i) + ccp->cc_sysbase) =
		    DWLPx_DIRECT_MAPPED_BASE | PCIA_WBASE_W_EN;

		REGVAL(PCIA_WMASK_B(i) + ccp->cc_sysbase) = 0;
		REGVAL(PCIA_TBASE_B(i) + ccp->cc_sysbase) = 0;
		REGVAL(PCIA_WBASE_B(i) + ccp->cc_sysbase) = 0;

		REGVAL(PCIA_WMASK_C(i) + ccp->cc_sysbase) = wmask;
		REGVAL(PCIA_TBASE_C(i) + ccp->cc_sysbase) = 0;
		REGVAL(PCIA_WBASE_C(i) + ccp->cc_sysbase) =
		    DWLPx_SG_MAPPED_BASE | PCIA_WBASE_W_EN | PCIA_WBASE_SG_EN;
		alpha_mb();
	}

	/* XXX XXX BEGIN XXX XXX */
	{							/* XXX */
		extern vm_offset_t alpha_XXX_dmamap_or;		/* XXX */
		alpha_XXX_dmamap_or = DWLPx_DIRECT_MAPPED_BASE;	/* XXX */
	}							/* XXX */
	/* XXX XXX END XXX XXX */
}

/*
 * Return the bus dma tag to be used for the specified bus type.
 * INTERNAL USE ONLY!
 */
bus_dma_tag_t
dwlpx_dma_get_tag(t, bustype)
	bus_dma_tag_t t;
	alpha_bus_t bustype;
{
	struct dwlpx_config *ccp = t->_cookie;
	extern int physmem;

	switch (bustype) {
	case ALPHA_BUS_PCI:
	case ALPHA_BUS_EISA:
		/*
		 * As best as I can tell from the DU source, you can't
		 * do DIRECT MAPPED and S/G at the same time.
		 */
#ifndef	MSS3_DEBUG_SG
		if (physmem <= btoc(2048LL << 20LL))
			return (&ccp->cc_dmat_direct);
#endif
		/* FALLTHROUGH */

	case ALPHA_BUS_ISA:
		/*
		 * ISA doesn't have enough address bits to use
		 * the direct-mapped DMA window, so we must use
		 * SGMAPs.
		 */
		return (&ccp->cc_dmat_sgmap);

	default:
		panic("dwlpx_dma_get_tag: shouldn't be here, really...");
	}
}

/*
 * Create a DWLPx SGMAP-mapped DMA map.
 */
int
dwlpx_bus_dmamap_create_sgmap(t, size, nsegments, maxsegsz, boundary,
    flags, dmamp)
	bus_dma_tag_t t;
	bus_size_t size;
	int nsegments;
	bus_size_t maxsegsz;
	bus_size_t boundary;
	int flags;
	bus_dmamap_t *dmamp;
{
	struct dwlpx_config *ccp = t->_cookie;
	bus_dmamap_t map;
	int error;

	error = _bus_dmamap_create(t, size, nsegments, maxsegsz,
	    boundary, flags, dmamp);
	if (error)
		return (error);

	map = *dmamp;

	if (flags & BUS_DMA_ALLOCNOW) {
		error = alpha_sgmap_alloc(map, round_page(size),
		    &ccp->cc_sgmap, flags);
		if (error)
			dwlpx_bus_dmamap_destroy_sgmap(t, map);
	}

	return (error);
}

/*
 * Destroy a DWLPx SGMAP-mapped DMA map.
 */
void
dwlpx_bus_dmamap_destroy_sgmap(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{
	struct dwlpx_config *ccp = t->_cookie;

	if (map->_dm_flags & DMAMAP_HAS_SGMAP)
		alpha_sgmap_free(map, &ccp->cc_sgmap);

	_bus_dmamap_destroy(t, map);
}

/*
 * Load a DWLPx SGMAP-mapped DMA map with a linear buffer.
 */
int
dwlpx_bus_dmamap_load_sgmap(t, map, buf, buflen, p, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
{
	struct dwlpx_config *ccp = t->_cookie;

	return (pci_sgmap_pte32_load(t, map, buf, buflen, p, flags,
	    &ccp->cc_sgmap));
}

/*
 * Load a DWLPx SGMAP-mapped DMA map with an mbuf chain.
 */
int
dwlpx_bus_dmamap_load_mbuf_sgmap(t, map, m, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct mbuf *m;
	int flags;
{
	struct dwlpx_config *ccp = t->_cookie;

	return (pci_sgmap_pte32_load_mbuf(t, map, m, flags, &ccp->cc_sgmap));
}

/*
 * Load a DWLPx SGMAP-mapped DMA map with a uio.
 */
int
dwlpx_bus_dmamap_load_uio_sgmap(t, map, uio, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct uio *uio;
	int flags;
{
	struct dwlpx_config *ccp = t->_cookie;

	return (pci_sgmap_pte32_load_uio(t, map, uio, flags, &ccp->cc_sgmap));
}

/*
 * Load a DWLPx SGMAP-mapped DMA map with raw memory.
 */
int
dwlpx_bus_dmamap_load_raw_sgmap(t, map, segs, nsegs, size, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	bus_dma_segment_t *segs;
	int nsegs;
	bus_size_t size;
	int flags;
{
	struct dwlpx_config *ccp = t->_cookie;

	return (pci_sgmap_pte32_load_raw(t, map, segs, nsegs, size, flags,
	    &ccp->cc_sgmap));
}

/*
 * Unload a DWLPx DMA map.
 */
void
dwlpx_bus_dmamap_unload_sgmap(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{
	struct dwlpx_config *ccp = t->_cookie;

	/*
	 * Invalidate any SGMAP page table entries used by this
	 * mapping.
	 */
	pci_sgmap_pte32_unload(t, map, &ccp->cc_sgmap);

	/*
	 * Do the generic bits of the unload.
	 */
	_bus_dmamap_unload(t, map);
}
