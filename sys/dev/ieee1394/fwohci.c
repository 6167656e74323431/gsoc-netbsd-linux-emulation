/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry.
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

/*
 * IEEE1394 Open Host Controller Interface
 *	based on OHCI Specification 1.1 (January 6, 2000)
 * The first version to support network interface part is wrtten by
 * Atsushi Onoe <onoe@netbsd.org>.
 */

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

#include <machine/bus.h>

#include <dev/ieee1394/ieee1394reg.h>
#include <dev/ieee1394/fwohcireg.h>

#include <dev/ieee1394/ieee1394var.h>
#include <dev/ieee1394/fwohcivar.h>

static const char * const ieee1394_speeds[] = { IEEE1394_SPD_STRINGS };

#if 0
static int fwohci_dnamem_alloc(struct fwohci_softc *sc, int size, int alignment,
			       bus_dmamap_t *mapp, caddr_t *kvap, int flags);
#endif

static int  fwohci_desc_alloc(struct fwohci_softc *);

static int  fwohci_ctx_alloc(struct fwohci_softc *, struct fwohci_ctx **,
		int, int);
static void fwohci_ctx_init(struct fwohci_softc *, struct fwohci_ctx *);

static int  fwohci_buf_alloc(struct fwohci_softc *, struct fwohci_buf *);
static void fwohci_buf_free(struct fwohci_softc *, struct fwohci_buf *);
static void fwohci_buf_init(struct fwohci_softc *);
static void fwohci_buf_next(struct fwohci_softc *, struct fwohci_ctx *);
static int  fwohci_buf_pktget(struct fwohci_softc *, struct fwohci_ctx *,
		caddr_t *, int);
static int  fwohci_buf_input(struct fwohci_softc *, struct fwohci_ctx *,
		struct fwohci_pkt *);

static void fwohci_phy_busreset(struct fwohci_softc *);

static int  fwohci_handler_set(struct fwohci_softc *, int, u_int32_t, u_int32_t,
		int (*)(struct fwohci_softc *, void *, struct fwohci_pkt *),
		void *);

static void fwohci_arrq_input(struct fwohci_softc *, struct fwohci_ctx *);
static void fwohci_arrs_input(struct fwohci_softc *, struct fwohci_ctx *);
static void fwohci_ir_input(struct fwohci_softc *, struct fwohci_ctx *);

static int  fwohci_at_output(struct fwohci_softc *, struct fwohci_ctx *,
		struct fwohci_pkt *);
static void fwohci_at_done(struct fwohci_softc *, struct fwohci_ctx *);
static void fwohci_atrs_output(struct fwohci_softc *, int, struct fwohci_pkt *,
		struct fwohci_pkt *);

static void fwohci_configrom_init(struct fwohci_softc *);

static void fwohci_selfid_init(struct fwohci_softc *);
static void fwohci_selfid_input(struct fwohci_softc *);

static void fwohci_csr_init(struct fwohci_softc *);
static int  fwohci_csr_input(struct fwohci_softc *, void *,
		struct fwohci_pkt *);

static void fwohci_uid_collect(struct fwohci_softc *);
static int  fwohci_uid_input(struct fwohci_softc *, void *,
		struct fwohci_pkt *);
static int  fwohci_uid_lookup(struct fwohci_softc *, u_int8_t *);

static int  fwohci_if_inreg(struct device *, u_int32_t, u_int32_t,
		void (*)(struct device *, struct mbuf *));
static int  fwohci_if_input(struct fwohci_softc *, void *, struct fwohci_pkt *);
static int  fwohci_if_output(struct device *, struct mbuf *,
		void (*)(struct device *, struct mbuf *));

int
fwohci_init(struct fwohci_softc *sc, const struct evcnt *ev)
{
	int i;
	u_int32_t val;
#if 0
	int error;
#endif

	evcnt_attach_dynamic(&sc->sc_intrcnt, EVCNT_TYPE_INTR, ev,
	    sc->sc_sc1394.sc1394_dev.dv_xname, "intr");

	OHCI_CSR_WRITE(sc, OHCI_REG_HCControlClear, OHCI_HCControl_SoftReset);
	/*
	 * Wait for reset completion
	 */
	for (i = 0; i < OHCI_LOOP; i++) {
		val = OHCI_CSR_READ(sc, OHCI_REG_HCControlClear);
		if ((val & OHCI_HCControl_SoftReset) == 0)
			break;
	}

	/* What dialect of OHCI is this device?
	 */
	val = OHCI_CSR_READ(sc, OHCI_REG_Version);
	printf("%s: OHCI %u.%u", sc->sc_sc1394.sc1394_dev.dv_xname,
	    OHCI_Version_GET_Version(val), OHCI_Version_GET_Revision(val));

	/* Is the Global UID ROM present?
	 */
	if ((val & OHCI_Version_GUID_ROM) == 0) {
		printf("\n%s: fatal: no global UID ROM\n", sc->sc_sc1394.sc1394_dev.dv_xname);
		return -1;
	} else {

		/* Extract the Global UID
		 */
		val = OHCI_CSR_READ(sc, OHCI_REG_GUIDHi);
		sc->sc_sc1394.sc1394_guid[0] = (val >> 24) & 0xff;
		sc->sc_sc1394.sc1394_guid[1] = (val >> 16) & 0xff;
		sc->sc_sc1394.sc1394_guid[2] = (val >>  8) & 0xff;
		sc->sc_sc1394.sc1394_guid[3] = (val >>  0) & 0xff;

		val = OHCI_CSR_READ(sc, OHCI_REG_GUIDLo);
		sc->sc_sc1394.sc1394_guid[4] = (val >> 24) & 0xff;
		sc->sc_sc1394.sc1394_guid[5] = (val >> 16) & 0xff;
		sc->sc_sc1394.sc1394_guid[6] = (val >>  8) & 0xff;
		sc->sc_sc1394.sc1394_guid[7] = (val >>  0) & 0xff;
	}

	printf(", %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	    sc->sc_sc1394.sc1394_guid[0], sc->sc_sc1394.sc1394_guid[1],
	    sc->sc_sc1394.sc1394_guid[2], sc->sc_sc1394.sc1394_guid[3],
	    sc->sc_sc1394.sc1394_guid[4], sc->sc_sc1394.sc1394_guid[5],
	    sc->sc_sc1394.sc1394_guid[6], sc->sc_sc1394.sc1394_guid[7]);

	/* Get the maximum link speed and receive size
	 */
	val = OHCI_CSR_READ(sc, OHCI_REG_BusOptions);
	sc->sc_sc1394.sc1394_link_speed =
	    (val & OHCI_BusOptions_LinkSpd_MASK)
		>> OHCI_BusOptions_LinkSpd_BITPOS;
	if (sc->sc_sc1394.sc1394_link_speed < IEEE1394_SPD_MAX) {
		printf(", %s", ieee1394_speeds[sc->sc_sc1394.sc1394_link_speed]);
	} else {
		printf(", unknown speed %u", sc->sc_sc1394.sc1394_link_speed);
	}

	/* MaxRec is encoded as log2(max_rec_octets)-1
	 */
	sc->sc_sc1394.sc1394_max_receive =
	    1 << (((val & OHCI_BusOptions_MaxRec_MASK)
		       >> OHCI_BusOptions_MaxRec_BITPOS) + 1);
	printf(", %u max_rec", sc->sc_sc1394.sc1394_max_receive);

	/*
	 * Count how many isochronous ctx we have.
	 */
	OHCI_CSR_WRITE(sc, OHCI_REG_IsoRecvIntMaskSet, 0xffffffff);
	val = OHCI_CSR_READ(sc, OHCI_REG_IsoRecvIntMaskClear);
	OHCI_CSR_WRITE(sc, OHCI_REG_IsoRecvIntMaskClear, 0xffffffff);
	for (i = 0; val != 0; val >>= 1) {
		if (val & 0x1)
			i++;
	}
	sc->sc_isoctx = i;
	printf(", %d iso_ctx", sc->sc_isoctx);

	printf("\n");

#if 0
	error = fwohci_dnamem_alloc(sc, OHCI_CONFIG_SIZE, OHCI_CONFIG_ALIGNMENT,
				    &sc->sc_configrom_map,
				    (caddr_t *) &sc->sc_configrom,
				    BUS_DMA_WAITOK|BUS_DMA_COHERENT);
	return error;
#endif

	/*
	 * Enable Link Power
	 */
	OHCI_CSR_WRITE(sc, OHCI_REG_HCControlSet, OHCI_HCControl_LPS);
	if (fwohci_desc_alloc(sc))
		return -1;

	/*
	 * Allocate DMA Context
	 */
	fwohci_ctx_alloc(sc, &sc->sc_ctx_arrq, OHCI_BUF_ARRQ_CNT,
	    OHCI_CTX_ASYNC_RX_REQUEST);
	fwohci_ctx_alloc(sc, &sc->sc_ctx_arrs, OHCI_BUF_ARRS_CNT,
	    OHCI_CTX_ASYNC_RX_RESPONSE);
	fwohci_ctx_alloc(sc, &sc->sc_ctx_atrq, OHCI_BUF_ATRQ_CNT,
	    OHCI_CTX_ASYNC_TX_REQUEST);
	fwohci_ctx_alloc(sc, &sc->sc_ctx_atrs, OHCI_BUF_ATRS_CNT,
	    OHCI_CTX_ASYNC_TX_RESPONSE);
	sc->sc_ctx_ir = malloc(sizeof(sc->sc_ctx_ir[0]) * sc->sc_isoctx,
	    M_DEVBUF, M_WAITOK);
	for (i = 0; i < sc->sc_isoctx; i++) {
		fwohci_ctx_alloc(sc, &sc->sc_ctx_ir[i],   OHCI_BUF_IR_CNT, i);
		sc->sc_ctx_ir[i]->fc_ppbmode = 1;
	}

	/*
	 * Allocate buffer for configuration ROM and SelfID buffer
	 */
	fwohci_buf_alloc(sc, &sc->sc_buf_cnfrom);
	fwohci_buf_alloc(sc, &sc->sc_buf_selfid);

	/*
	 * First, initilize CSRs to default settings.
	 */
	val = OHCI_CSR_READ(sc, OHCI_REG_BusOptions);
#if 0
	val |= OHCI_BusOptions_BMC | OHCI_BusOptions_ISC |
		OHCI_BusOptions_CMC | OHCI_BusOptions_IRMC;
#endif
	OHCI_CSR_WRITE(sc, OHCI_REG_BusOptions, val);
	for (i = 0; i < sc->sc_isoctx; i++) {
		OHCI_SYNC_RX_DMA_WRITE(sc, i, OHCI_SUBREG_ContextControlClear,
		    ~0);
	}
	fwohci_configrom_init(sc);
	fwohci_selfid_init(sc);
	fwohci_buf_init(sc);
	fwohci_csr_init(sc);

	/*
	 * Final CSR settings.
	 */
	OHCI_CSR_WRITE(sc, OHCI_REG_LinkControlClear,
	    OHCI_LinkControl_CycleSource);
	OHCI_CSR_WRITE(sc, OHCI_REG_LinkControlSet,
	    OHCI_LinkControl_CycleTimerEnable | OHCI_LinkControl_RcvSelfID |
	    OHCI_LinkControl_RcvPhyPkt);

	OHCI_CSR_WRITE(sc, OHCI_REG_ATRetries, 0x00000888);	/*XXX*/

	/* clear receive filter */
	OHCI_CSR_WRITE(sc, OHCI_REG_IRMultiChanMaskHiClear, ~0);
	OHCI_CSR_WRITE(sc, OHCI_REG_IRMultiChanMaskLoClear, ~0);
	OHCI_CSR_WRITE(sc, OHCI_REG_AsynchronousRequestFilterHiSet, 0x80000000);

	OHCI_CSR_WRITE(sc, OHCI_REG_HCControlClear,
	    OHCI_HCControl_NoByteSwapData);
	OHCI_CSR_WRITE(sc, OHCI_REG_HCControlSet, OHCI_HCControl_LinkEnable);

	OHCI_CSR_WRITE(sc, OHCI_REG_IntMaskClear, ~0);
	OHCI_CSR_WRITE(sc, OHCI_REG_IntMaskSet, OHCI_Int_BusReset |
	    OHCI_Int_SelfIDComplete | OHCI_Int_IsochRx | OHCI_Int_IsochTx |
	    OHCI_Int_RSPkt | OHCI_Int_RQPkt | OHCI_Int_ARRS | OHCI_Int_ARRQ |
	    OHCI_Int_RespTxComplete | OHCI_Int_ReqTxComplete);
	OHCI_CSR_WRITE(sc, OHCI_REG_IntMaskSet, OHCI_Int_CycleTooLong |
	    OHCI_Int_UnrecoverableError | OHCI_Int_CycleInconsistent |
	    OHCI_Int_LockRespErr | OHCI_Int_PostedWriteErr);
	OHCI_CSR_WRITE(sc, OHCI_REG_IsoXmitIntMaskSet, ~0);
	OHCI_CSR_WRITE(sc, OHCI_REG_IsoRecvIntMaskSet, ~0);
	OHCI_CSR_WRITE(sc, OHCI_REG_IntMaskSet, OHCI_Int_MasterEnable);
	config_defer(&sc->sc_sc1394.sc1394_dev,
	    (void (*)(struct device *))fwohci_phy_busreset);

	sc->sc_sc1394.sc1394_ifinreg = fwohci_if_inreg;
	sc->sc_sc1394.sc1394_ifoutput = fwohci_if_output;
	sc->sc_sc1394.sc1394_if = config_found(&sc->sc_sc1394.sc1394_dev,
	    "fw", fwohci_print);

	return 0;
}

int
fwohci_intr(void *arg)
{
	struct fwohci_softc * const sc = arg;
	int i;
	int progress = 0;
	u_int32_t intmask, iso;

	for (;;) {
		intmask = OHCI_CSR_READ(sc, OHCI_REG_IntEventClear);
		if (intmask == 0)
			return progress;
#ifdef FW_DEBUG
		printf("%s: intmask=0x%08x:", sc->sc_sc1394.sc1394_dev.dv_xname, intmask);
		if (intmask & OHCI_Int_CycleTooLong)
			printf(" CycleTooLong");
		if (intmask & OHCI_Int_UnrecoverableError)
			printf(" UnrecoverableError");
		if (intmask & OHCI_Int_CycleInconsistent)
			printf(" CycleInconsistent");
		if (intmask & OHCI_Int_BusReset)
			printf(" BusReset");
		if (intmask & OHCI_Int_SelfIDComplete)
			printf(" SelfIDComplete");
		if (intmask & OHCI_Int_LockRespErr)
			printf(" LockRespErr");
		if (intmask & OHCI_Int_PostedWriteErr)
			printf(" PostedWriteErr");
		if (intmask & OHCI_Int_ReqTxComplete)
			printf(" ReqTxComplete(0x%08x)",
			    OHCI_ASYNC_DMA_READ(sc, OHCI_CTX_ASYNC_TX_REQUEST,
			    OHCI_SUBREG_ContextControlClear));
		if (intmask & OHCI_Int_RespTxComplete)
			printf(" RespTxComplete(0x%08x)",
			    OHCI_ASYNC_DMA_READ(sc, OHCI_CTX_ASYNC_TX_RESPONSE,
			    OHCI_SUBREG_ContextControlClear));
		if (intmask & OHCI_Int_ARRS)
			printf(" ARRS(0x%08x)",
			    OHCI_ASYNC_DMA_READ(sc, OHCI_CTX_ASYNC_RX_RESPONSE,
			    OHCI_SUBREG_ContextControlClear));
		if (intmask & OHCI_Int_ARRQ)
			printf(" ARRQ(0x%08x)",
			    OHCI_ASYNC_DMA_READ(sc, OHCI_CTX_ASYNC_RX_REQUEST,
			    OHCI_SUBREG_ContextControlClear));
		if (intmask & OHCI_Int_IsochRx)
			printf(" IsochRx");
		if (intmask & OHCI_Int_IsochTx)
			printf(" IsochTx");
		if (intmask & OHCI_Int_RQPkt)
			printf(" RQPkt");
		if (intmask & OHCI_Int_RSPkt)
			printf(" RSPkt");
		printf("\n");
#endif /* FW_DEBUG */
		if (intmask & OHCI_Int_BusReset) {
			if (sc->sc_uidtbl != NULL) {
				free(sc->sc_uidtbl, M_DEVBUF);
				sc->sc_uidtbl = NULL;
			}
			OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_TX_REQUEST,
			    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
			OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_TX_RESPONSE,
			    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
			fwohci_buf_init(sc);
		}
		if (intmask & OHCI_Int_SelfIDComplete) {
			fwohci_selfid_input(sc);
			fwohci_uid_collect(sc);
		}

		if (intmask & OHCI_Int_ReqTxComplete)
			fwohci_at_done(sc, sc->sc_ctx_atrq);
		if (intmask & OHCI_Int_RespTxComplete)
			fwohci_at_done(sc, sc->sc_ctx_atrs);
		if (intmask & OHCI_Int_RQPkt)
			fwohci_arrq_input(sc, sc->sc_ctx_arrq);
		if (intmask & OHCI_Int_RSPkt)
			fwohci_arrs_input(sc, sc->sc_ctx_arrs);

		if (intmask & OHCI_Int_IsochTx) {
			iso = OHCI_CSR_READ(sc, OHCI_REG_IsoXmitIntEventClear);
			OHCI_CSR_WRITE(sc, OHCI_REG_IsoXmitIntEventClear, iso);
		}
		if (intmask & OHCI_Int_IsochRx) {
			iso = OHCI_CSR_READ(sc, OHCI_REG_IsoRecvIntEventClear);
			for (i = 0; i < sc->sc_isoctx; i++) {
				if (iso & (1 << i))
					fwohci_ir_input(sc, sc->sc_ctx_ir[i]);
			}
			OHCI_CSR_WRITE(sc, OHCI_REG_IsoRecvIntEventClear, iso);
		}

		OHCI_CSR_WRITE(sc, OHCI_REG_IntEventClear, intmask);
		if (!progress) {
			sc->sc_intrcnt.ev_count++;
			progress = 1;
		}
	}
}

#if 0
static int
fwohci_dnamem_alloc(struct fwohci_softc *sc, int size, int alignment,
		    bus_dmamap_t *mapp, caddr_t *kvap, int flags)
{
	bus_dma_segment_t segs[1];
	int error, nsegs, steps;

	steps = 0;
	error = bus_dmamem_alloc(sc->sc_dmat, size, alignment, alignment,
				 segs, 1, &nsegs, flags);
	if (error)
		goto cleanup;

	steps = 1;
	error = bus_dmamem_map(sc->sc_dmat, segs, nsegs, segs[0].ds_len,
			       kvap, flags);
	if (error)
		goto cleanup;

	if (error == 0)
		error = bus_dmamap_create(sc->sc_dmat, size, 1, alignment,
					  size, flags, mapp);
	if (error)
		goto cleanup;
	if (error == 0)
		error = bus_dmamap_load(sc->sc_dmat, *mapp, *kvap, size, NULL, flags);
	if (error)
		goto cleanup;

cleanup:
	switch (steps) {
	case 1:
		bus_dmamem_free(sc->sc_dmat, segs, nsegs);
	}

	return error;
}
#endif

int
fwohci_print(void *aux, const char *pnp)
{
	char *name = aux;

	if (pnp)
		printf("%s at %s", name, pnp);

	return UNCONF;
}

/*
 * COMMON FUNCTIONS
 */

/*
 * Initiate Bus Reset
 */
static void
fwohci_phy_busreset(struct fwohci_softc *sc)
{
	int i;
	u_int8_t reg;
	u_int32_t val;

	reg = 1;
	OHCI_CSR_WRITE(sc, OHCI_REG_PhyControl,
	    OHCI_PhyControl_RdReg | (reg << OHCI_PhyControl_RegAddr_BITPOS));
	for (i = 0; i < OHCI_LOOP; i++) {
		if (OHCI_CSR_READ(sc, OHCI_REG_PhyControl) &
		    OHCI_PhyControl_RdDone)
			break;
	}
	val = OHCI_CSR_READ(sc, OHCI_REG_PhyControl);
	val = (val & OHCI_PhyControl_RdData) >> OHCI_PhyControl_RdData_BITPOS;
	val = (val & 0x80) | 0x40 | 0x3f;	/* XXX: gap */
	OHCI_CSR_WRITE(sc, OHCI_REG_PhyControl, OHCI_PhyControl_WrReg |
	    (reg << OHCI_PhyControl_RegAddr_BITPOS) |
	    (val << OHCI_PhyControl_WrData_BITPOS));
	for (i = 0; i < OHCI_LOOP; i++) {
		if (!(OHCI_CSR_READ(sc, OHCI_REG_PhyControl) &
		    OHCI_PhyControl_WrReg))
			break;
	}
}

/*
 * Descriptor for context DMA.
 */
static int
fwohci_desc_alloc(struct fwohci_softc *sc)
{
	int error;

	/*
	 * allocate descriptor buffer
	 */

	sc->sc_descsize = sizeof(struct fwohci_desc) *
	    (OHCI_BUF_ARRQ_CNT + OHCI_BUF_ARRS_CNT +
	    OHCI_BUF_ATRQ_CNT + OHCI_BUF_ATRS_CNT +
	    OHCI_BUF_IR_CNT * sc->sc_isoctx + 2);

	if ((error = bus_dmamem_alloc(sc->sc_dmat, sc->sc_descsize,
	    OHCI_PAGE_SIZE, 0, &sc->sc_dseg, 1, &sc->sc_dnseg, 0)) != 0) {
		printf("%s: unable to allocate descriptor buffer, error = %d\n",
		    sc->sc_sc1394.sc1394_dev.dv_xname, error);
		goto fail_0;
	}

	if ((error = bus_dmamem_map(sc->sc_dmat, &sc->sc_dseg, sc->sc_dnseg,
	    sc->sc_descsize, &sc->sc_desc, BUS_DMA_COHERENT)) != 0) {
		printf("%s: unable to map descriptor buffer, error = %d\n",
		    sc->sc_sc1394.sc1394_dev.dv_xname, error);
		goto fail_1;
	}

	if ((error = bus_dmamap_create(sc->sc_dmat, sc->sc_descsize,
	    sc->sc_dnseg, sc->sc_descsize, 0, 0, &sc->sc_ddmamap)) != 0) {
		printf("%s: unable to create descriptor buffer DMA map, "
		    "error = %d\n", sc->sc_sc1394.sc1394_dev.dv_xname, error);
		goto fail_2;
	}

	if ((error = bus_dmamap_load(sc->sc_dmat, sc->sc_ddmamap, sc->sc_desc,
	    sc->sc_descsize, NULL, 0)) != 0) {
		printf("%s: unable to load descriptor buffer DMA map, "
		    "error = %d\n", sc->sc_sc1394.sc1394_dev.dv_xname, error);
		goto fail_3;
	}

	return 0;

  fail_3:
	bus_dmamap_destroy(sc->sc_dmat, sc->sc_ddmamap);
  fail_2:
	bus_dmamem_unmap(sc->sc_dmat, sc->sc_desc, sc->sc_descsize);
  fail_1:
	bus_dmamem_free(sc->sc_dmat, &sc->sc_dseg, sc->sc_dnseg);
  fail_0:
	return error;
}

/*
 * Asyncronous/Isochronous Transmit/Receive Context
 */
static int
fwohci_ctx_alloc(struct fwohci_softc *sc, struct fwohci_ctx **fcp,
    int bufcnt, int ctx)
{
	int i, error;
	struct fwohci_ctx *fc;
	struct fwohci_buf *fb;
	struct fwohci_desc *fd;

	fc = malloc(sizeof(*fc) + sizeof(*fb) * bufcnt, M_DEVBUF, M_WAITOK);
	memset(fc, 0, sizeof(*fc) + sizeof(*fb) * bufcnt);
	LIST_INIT(&fc->fc_handler);
	TAILQ_INIT(&fc->fc_buf);
	TAILQ_INIT(&fc->fc_busy);
	fc->fc_ctx = ctx;
	fc->fc_bufcnt = bufcnt;
	fb = (struct fwohci_buf *)&fc[1];
	for (i = 0; i < bufcnt; i++, fb++) {
		if ((error = fwohci_buf_alloc(sc, fb)) != 0)
			goto fail;
		fd = (struct fwohci_desc *)sc->sc_desc + sc->sc_descfree++;
		fb->fb_desc = fd;
		fb->fb_daddr = sc->sc_ddmamap->dm_segs[0].ds_addr +
		    ((caddr_t)fd - sc->sc_desc);
		fd->fd_flags = OHCI_DESC_INPUT | OHCI_DESC_STATUS |
		    OHCI_DESC_INTR_ALWAYS | OHCI_DESC_BRANCH;
		fd->fd_reqcount = fb->fb_dmamap->dm_segs[0].ds_len;
		fd->fd_data = fb->fb_dmamap->dm_segs[0].ds_addr;
		TAILQ_INSERT_TAIL(&fc->fc_buf, fb, fb_list);
	}
	*fcp = fc;
	return 0;

  fail:
	while (i-- > 0)
		fwohci_buf_free(sc, --fb);
	free(fc, M_DEVBUF);
	return error;
}

static void
fwohci_ctx_init(struct fwohci_softc *sc, struct fwohci_ctx *fc)
{
	struct fwohci_buf *fb, *nfb;
	struct fwohci_desc *fd;

	for (fb = TAILQ_FIRST(&fc->fc_buf); fb != NULL; fb = nfb) {
		nfb = TAILQ_NEXT(fb, fb_list);
		fb->fb_off = 0;
		fd = fb->fb_desc;
		fd->fd_branch = (nfb != NULL) ? (nfb->fb_daddr | 1) : 0;
		fd->fd_rescount = fd->fd_reqcount;
	}
}

/*
 * DMA data buffer
 */
static int
fwohci_buf_alloc(struct fwohci_softc *sc, struct fwohci_buf *fb)
{
	int error;

	if ((error = bus_dmamem_alloc(sc->sc_dmat, OHCI_PAGE_SIZE,
	    OHCI_PAGE_SIZE, 0, &fb->fb_seg, 1, &fb->fb_nseg, 0)) != 0) {
		printf("%s: unable to allocate buffer, error = %d\n",
		    sc->sc_sc1394.sc1394_dev.dv_xname, error);
		goto fail_0;
	}

	if ((error = bus_dmamem_map(sc->sc_dmat, &fb->fb_seg,
	    fb->fb_nseg, OHCI_PAGE_SIZE, &fb->fb_buf, 0)) != 0) {
		printf("%s: unable to map buffer, error = %d\n",
		    sc->sc_sc1394.sc1394_dev.dv_xname, error);
		goto fail_1;
	}

	if ((error = bus_dmamap_create(sc->sc_dmat, OHCI_PAGE_SIZE,
	    fb->fb_nseg, OHCI_PAGE_SIZE, 0, 0, &fb->fb_dmamap)) != 0) {
		printf("%s: unable to create buffer DMA map, "
		    "error = %d\n", sc->sc_sc1394.sc1394_dev.dv_xname,
		    error);
		goto fail_2;
	}

	if ((error = bus_dmamap_load(sc->sc_dmat, fb->fb_dmamap,
	    fb->fb_buf, OHCI_PAGE_SIZE, NULL, 0)) != 0) {
		printf("%s: unable to load buffer DMA map, "
		    "error = %d\n", sc->sc_sc1394.sc1394_dev.dv_xname,
		    error);
		goto fail_3;
	}

	return 0;

	bus_dmamap_unload(sc->sc_dmat, fb->fb_dmamap);
  fail_3:
	bus_dmamap_destroy(sc->sc_dmat, fb->fb_dmamap);
  fail_2:
	bus_dmamem_unmap(sc->sc_dmat, fb->fb_buf, OHCI_PAGE_SIZE);
  fail_1:
	bus_dmamem_free(sc->sc_dmat, &fb->fb_seg, fb->fb_nseg);
  fail_0:
	return error;
}

static void
fwohci_buf_free(struct fwohci_softc *sc, struct fwohci_buf *fb)
{

	bus_dmamap_unload(sc->sc_dmat, fb->fb_dmamap);
	bus_dmamap_destroy(sc->sc_dmat, fb->fb_dmamap);
	bus_dmamem_unmap(sc->sc_dmat, fb->fb_buf, OHCI_PAGE_SIZE);
	bus_dmamem_free(sc->sc_dmat, &fb->fb_seg, fb->fb_nseg);
}

static void
fwohci_buf_init(struct fwohci_softc *sc)
{
	int i;
	struct fwohci_buf *fb;

	/*
	 * Stop the transmitter and receiver.
	 */
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_TX_REQUEST,
	    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_TX_RESPONSE,
	    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_RX_REQUEST,
	    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_RX_RESPONSE,
	    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
	for (i = 0; i < sc->sc_isoctx; i++) {
		OHCI_SYNC_RX_DMA_WRITE(sc, i,
		    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
	}

	/*
	 * Initialize for Asynchronous Transmit Request.
	 */
	while ((fb = TAILQ_FIRST(&sc->sc_ctx_atrq->fc_busy)) != NULL) {
		TAILQ_REMOVE(&sc->sc_ctx_atrq->fc_busy, fb, fb_list);
		if (fb->fb_m != NULL) {
			if (fb->fb_callback != NULL) {
				(*fb->fb_callback)
				    (sc->sc_sc1394.sc1394_if, fb->fb_m);
				fb->fb_callback = NULL;
			} else
				m_freem(fb->fb_m);
			fb->fb_m = NULL;
		}
		TAILQ_INSERT_TAIL(&sc->sc_ctx_atrq->fc_buf, fb, fb_list);
	}
	sc->sc_ctx_atrq->fc_branch = NULL;

	/*
	 * Initialize for Asynchronous Transmit Response.
	 */
	while ((fb = TAILQ_FIRST(&sc->sc_ctx_atrs->fc_busy)) != NULL) {
		TAILQ_REMOVE(&sc->sc_ctx_atrs->fc_busy, fb, fb_list);
		if (fb->fb_m != NULL) {
			if (fb->fb_callback != NULL) {
				(*fb->fb_callback)
				    (sc->sc_sc1394.sc1394_if, fb->fb_m);
				fb->fb_callback = NULL;
			} else
				m_freem(fb->fb_m);
			fb->fb_m = NULL;
		}
		TAILQ_INSERT_TAIL(&sc->sc_ctx_atrs->fc_buf, fb, fb_list);
	}
	sc->sc_ctx_atrq->fc_branch = NULL;

	/*
	 * Initialize for Asynchronous Receive Request.
	 */
	fwohci_ctx_init(sc, sc->sc_ctx_arrq);
	fb = TAILQ_FIRST(&sc->sc_ctx_arrq->fc_buf);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_RX_REQUEST,
	    OHCI_SUBREG_CommandPtr, fb->fb_daddr | 1);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_RX_REQUEST,
	    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_RUN);

	/*
	 * Initialize for Asynchronous Receive Response.
	 */
	fwohci_ctx_init(sc, sc->sc_ctx_arrs);
	fb = TAILQ_FIRST(&sc->sc_ctx_arrs->fc_buf);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_RX_RESPONSE,
	    OHCI_SUBREG_CommandPtr, fb->fb_daddr | 1);
	OHCI_ASYNC_DMA_WRITE(sc, OHCI_CTX_ASYNC_RX_RESPONSE,
	    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_RUN);

	/*
	 * Initialize for Isochronous Receive.
	 */
	for (i = 0; i < sc->sc_isoctx; i++) {
		fwohci_ctx_init(sc, sc->sc_ctx_ir[i]);
		fb = TAILQ_FIRST(&sc->sc_ctx_ir[i]->fc_buf);
		OHCI_SYNC_RX_DMA_WRITE(sc, 0, OHCI_SUBREG_CommandPtr,
		    fb->fb_daddr | 1);
		OHCI_SYNC_RX_DMA_WRITE(sc, 0, OHCI_SUBREG_ContextControlClear,
		    OHCI_CTXCTL_RX_BUFFER_FILL |
		    OHCI_CTXCTL_RX_CYCLE_MATCH_ENABLE |
		    OHCI_CTXCTL_RX_MULTI_CHAN_MODE |
		    OHCI_CTXCTL_RX_DUAL_BUFFER_MODE);
		OHCI_SYNC_RX_DMA_WRITE(sc, 0, OHCI_SUBREG_ContextControlSet,
		    OHCI_CTXCTL_RX_ISOCH_HEADER);
		if (LIST_FIRST(&sc->sc_ctx_ir[i]->fc_handler) != NULL) {
			OHCI_SYNC_RX_DMA_WRITE(sc, i,
			    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_RUN);
		}
	}
}

static void
fwohci_buf_next(struct fwohci_softc *sc, struct fwohci_ctx *fc)
{
	struct fwohci_buf *fb, *tfb;

	while ((fb = TAILQ_FIRST(&fc->fc_buf)) != NULL) {
		if (fb->fb_off != fb->fb_desc->fd_reqcount ||
		    fb->fb_desc->fd_rescount != 0)
			break;
		TAILQ_REMOVE(&fc->fc_buf, fb, fb_list);
		fb->fb_desc->fd_rescount = fb->fb_desc->fd_reqcount;
		fb->fb_off = 0;
		fb->fb_desc->fd_branch = 0;
		tfb = TAILQ_LAST(&fc->fc_buf, fwohci_buf_s);
		tfb->fb_desc->fd_branch = fb->fb_daddr | 1;
		TAILQ_INSERT_TAIL(&fc->fc_buf, fb, fb_list);
	}
}

static int
fwohci_buf_pktget(struct fwohci_softc *sc, struct fwohci_ctx *fc, caddr_t *pp,
    int len)
{
	struct fwohci_buf *fb;
	struct fwohci_desc *fd;
	int bufend;

	fb = TAILQ_FIRST(&fc->fc_buf);
  again:
	fd = fb->fb_desc;
#ifdef FW_DEBUG
printf("fwohci_buf_pktget: desc %d, off %d, req %d, res %d\n", fd - (struct fwohci_desc *)sc->sc_desc, fb->fb_off, fd->fd_reqcount, fd->fd_rescount);
#endif
	bufend = fd->fd_reqcount - fd->fd_rescount;
	if (fb->fb_off >= bufend) {
		if (fc->fc_ppbmode && fb->fb_off > 0) {
			fb->fb_off = fd->fd_reqcount;
			fd->fd_rescount = 0;
		}
		if (fd->fd_rescount == 0) {
			if ((fb = TAILQ_NEXT(fb, fb_list)) != NULL)
				goto again;
		}
		return 0;
	}
	if (fb->fb_off + len > bufend)
		len = bufend - fb->fb_off;
	*pp = fb->fb_buf + fb->fb_off;
	fb->fb_off += roundup(len, 4);
	return len;
}

static int
fwohci_buf_input(struct fwohci_softc *sc, struct fwohci_ctx *fc,
    struct fwohci_pkt *pkt)
{
	caddr_t p;
	int len, count, i;

	/* get first quadlet */
	count = 4;
	if (fc->fc_ppbmode) {
		/*
		 * get trailer first, may be bogus data unless status update
		 * in descriptor is set.
		 */
		len = fwohci_buf_pktget(sc, fc, (caddr_t *)&pkt->fp_trail,
		    sizeof(pkt->fp_trail));
		if (len <= 0)
			return 0;
	}
	len = fwohci_buf_pktget(sc, fc, &p, count);
	if (len <= 0) {
#ifdef FW_DEBUG
		printf("fwohci_buf_input: no input\n");
#endif
		return 0;
	}
	pkt->fp_hdr[0] = *(u_int32_t *)p;
	pkt->fp_tcode = (pkt->fp_hdr[0] & 0x000000f0) >> 4;
	switch (pkt->fp_tcode) {
	case IEEE1394_TCODE_WRITE_REQ_QUAD:
	case IEEE1394_TCODE_READ_RESP_QUAD:
		pkt->fp_hlen = 12;
		pkt->fp_dlen = 4;
		break;
	case IEEE1394_TCODE_WRITE_REQ_BLOCK:
	case IEEE1394_TCODE_READ_RESP_BLOCK:
	case IEEE1394_TCODE_LOCK_REQ:
	case IEEE1394_TCODE_LOCK_RESP:
		pkt->fp_hlen = 16;
		break;
	case IEEE1394_TCODE_STREAM_DATA:
		pkt->fp_hlen = 4;
		pkt->fp_dlen = pkt->fp_hdr[0] >> 16;
		break;
	default:
		pkt->fp_hlen = 12;
		pkt->fp_dlen = 0;
		break;
	}

	/* get header */
	while (count < pkt->fp_hlen) {
		len = fwohci_buf_pktget(sc, fc, &p, pkt->fp_hlen - count);
		if (len == 0) {
			printf("fwohci_buf_input: malformed input 1: %d\n",
			    pkt->fp_hlen - count);
			return 0;
		}
		memcpy((caddr_t)pkt->fp_hdr + count, p, len);
		count += len;
	}
	if (pkt->fp_hlen == 16)
		pkt->fp_dlen = pkt->fp_hdr[3] >> 16;
#ifdef FW_DEBUG
	printf("fwohci_buf_input: tcode=0x%x, hlen=%d, dlen=%d\n",
	    pkt->fp_tcode, pkt->fp_hlen, pkt->fp_dlen);
#endif

	/* get data */
	count = 0;
	i = 0;
	while (count < pkt->fp_dlen) {
		len = fwohci_buf_pktget(sc, fc,
		    (caddr_t *)&pkt->fp_iov[i].iov_base,
		    pkt->fp_dlen - count);
		if (len == 0) {
			printf("fwohci_buf_input: malformed input 2: %d\n",
			    pkt->fp_hlen - count);
			return 0;
		}
		pkt->fp_iov[i++].iov_len = len;
		count += len;
	}

	if (!fc->fc_ppbmode) {
		/* get trailer */
		len = fwohci_buf_pktget(sc, fc, (caddr_t *)&pkt->fp_trail,
		    sizeof(pkt->fp_trail));
		if (len <= 0) {
			printf("fwohci_buf_input: malformed input 3: %d\n",
			    pkt->fp_hlen - count);
			return 0;
		}
	}
	return 1;
}

static int
fwohci_handler_set(struct fwohci_softc *sc,
    int tcode, u_int32_t key1, u_int32_t key2,
    int (*handler)(struct fwohci_softc *, void *, struct fwohci_pkt *),
    void *arg)
{
	struct fwohci_ctx *fc;
	struct fwohci_handler *fh;
	int i;

	if (tcode == IEEE1394_TCODE_STREAM_DATA) {
		for (i = 0; ; i++) {
			if (i == sc->sc_isoctx) {
				/* no more free ctx */
				return ENOMEM;
			}
			fc = sc->sc_ctx_ir[i];
			fh = LIST_FIRST(&fc->fc_handler);
			if (fh == NULL)
				break;
			if (fh->fh_tcode == tcode && fh->fh_key1 == key1 &&
			    fh->fh_key2 == key2)
				break;
		}
	} else {
		switch (tcode) {
		case IEEE1394_TCODE_WRITE_REQ_QUAD:
		case IEEE1394_TCODE_WRITE_REQ_BLOCK:
		case IEEE1394_TCODE_READ_REQ_QUAD:
		case IEEE1394_TCODE_READ_REQ_BLOCK:
		case IEEE1394_TCODE_LOCK_REQ:
			fc = sc->sc_ctx_arrq;
			break;
		case IEEE1394_TCODE_WRITE_RESP:
		case IEEE1394_TCODE_READ_RESP_QUAD:
		case IEEE1394_TCODE_READ_RESP_BLOCK:
		case IEEE1394_TCODE_LOCK_RESP:
			fc = sc->sc_ctx_arrs;
			break;
		default:
			return EIO;
		}
		for (fh = LIST_FIRST(&fc->fc_handler); fh != NULL;
		    fh = LIST_NEXT(fh, fh_list)) {
			if (fh->fh_tcode == tcode && fh->fh_key1 == key1 &&
			    fh->fh_key2 == key2)
				break;
		}
	}
	if (handler == NULL) {
		if (fh != NULL)
			LIST_REMOVE(fh, fh_list);
		return 0;
	}
	if (fh == NULL) {
		fh = malloc(sizeof(*fh), M_DEVBUF, M_NOWAIT);
		if (fh == NULL)
			return ENOMEM;
		LIST_INSERT_HEAD(&fc->fc_handler, fh, fh_list);
	}
	fh->fh_tcode = tcode;
	fh->fh_key1 = key1;
	fh->fh_key2 = key2;
	fh->fh_handler = handler;
	fh->fh_handarg = arg;

	if (tcode == IEEE1394_TCODE_STREAM_DATA) {
		OHCI_SYNC_RX_DMA_WRITE(sc, fc->fc_ctx, OHCI_SUBREG_ContextMatch,
		    (OHCI_CTXMATCH_TAG0 << key2) | key1);
	}
	return 0;
}

/*
 * Asyncronous Receive Requests input frontend.
 */
static void
fwohci_arrq_input(struct fwohci_softc *sc, struct fwohci_ctx *fc)
{
	int rcode;
	u_int32_t key1, key2;
	struct fwohci_handler *fh;
	struct fwohci_pkt pkt, res;

	while (fwohci_buf_input(sc, fc, &pkt)) {
		key1 = pkt.fp_hdr[1] & 0xffff;
		key2 = pkt.fp_hdr[2];
		memset(&res, 0, sizeof(res));
		for (fh = LIST_FIRST(&fc->fc_handler); fh != NULL;
		    fh = LIST_NEXT(fh, fh_list)) {
			if (pkt.fp_tcode == fh->fh_tcode &&
			    key1 == fh->fh_key1 &&
			    key2 == fh->fh_key2) {
				rcode = (*fh->fh_handler)(sc, fh->fh_handarg,
				    &pkt);
				break;
			}
		}
		if (fh == NULL) {
			rcode = IEEE1394_RCODE_ADDRESS_ERROR;
#ifdef FW_DEBUG
			printf("fwohci_arrq_input: no listener: tcode 0x%x, "
			    "addr=0x%04x %08x\n", pkt.fp_tcode,
			    key1, key2);
#endif
		}
		if (((*pkt.fp_trail & 0x001f0000) >> 16) !=
		    OHCI_CTXCTL_EVENT_ACK_PENDING)
			continue;
		if (rcode != -1)
			fwohci_atrs_output(sc, rcode, &pkt, &res);
	}
	fwohci_buf_next(sc, fc);
	OHCI_ASYNC_DMA_WRITE(sc, fc->fc_ctx,
	    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_WAKE);
}

/*
 * Asynchronous Receive Response input frontend.
 */
static void
fwohci_arrs_input(struct fwohci_softc *sc, struct fwohci_ctx *fc)
{
	struct fwohci_pkt pkt;
	struct fwohci_handler *fh;
	u_int16_t srcid;
	int rcode, tlabel;

	while (fwohci_buf_input(sc, fc, &pkt)) {
		srcid = pkt.fp_hdr[1] >> 16;
		rcode = (pkt.fp_hdr[1] & 0x0000f000) >> 12;
		tlabel = (pkt.fp_hdr[0] & 0x0000fc00) >> 10;
#ifdef FW_DEBUG
		printf("fwohci_arrs_input: tcode 0x%x, from 0x%04x, tlabel 0x%x, rcode 0x%x, hlen %d, dlen %d\n",
		    pkt.fp_tcode, srcid, tlabel, rcode, pkt.fp_hlen, pkt.fp_dlen);
#endif
		for (fh = LIST_FIRST(&fc->fc_handler); fh != NULL;
		    fh = LIST_NEXT(fh, fh_list)) {
			if (pkt.fp_tcode == fh->fh_tcode &&
			    (srcid & OHCI_NodeId_NodeNumber) == fh->fh_key1 &&
			    tlabel == fh->fh_key2) {
				(*fh->fh_handler)(sc, fh->fh_handarg, &pkt);
				LIST_REMOVE(fh, fh_list);
				free(fh, M_DEVBUF);
				break;
			}
		}
#ifdef FW_DEBUG
		if (fh == NULL)
			printf("fwohci_arrs_input: no lister\n");
#endif
	}
	fwohci_buf_next(sc, fc);
	OHCI_ASYNC_DMA_WRITE(sc, fc->fc_ctx,
	    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_WAKE);
}

/*
 * Isochronous Receive input frontend.
 */
static void
fwohci_ir_input(struct fwohci_softc *sc, struct fwohci_ctx *fc)
{
	int rcode, chan, tag;
	struct iovec *iov;
	struct fwohci_handler *fh;
	struct fwohci_pkt pkt;

	while (fwohci_buf_input(sc, fc, &pkt)) {
		chan = (pkt.fp_hdr[0] & 0x00003f00) >> 8;
		tag  = (pkt.fp_hdr[0] & 0x0000c000) >> 14;
#ifdef FW_DEBUG
		printf("fwohci_ir_input: hdr 0x%08x, tcode %d, hlen %d, dlen %d\n", pkt.fp_hdr[0], pkt.fp_tcode, pkt.fp_hlen, pkt.fp_dlen);
#endif
		if (tag == IEEE1394_TAG_GASP) {
			/*
			 * The pkt with tag=3 is GASP format.
			 * Move GASP header to header part.
			 */
			if (pkt.fp_dlen < 8)
				continue;
			iov = pkt.fp_iov;
			/* assuming pkt per buffer mode */
			memcpy(pkt.fp_hdr + 1, iov->iov_base, 8);
			iov->iov_base = (caddr_t)iov->iov_base + 8;
			iov->iov_len -= 8;
			pkt.fp_hlen += 8;
			pkt.fp_dlen -= 8;
		}
		for (fh = LIST_FIRST(&fc->fc_handler); fh != NULL;
		    fh = LIST_NEXT(fh, fh_list)) {
			if (pkt.fp_tcode == fh->fh_tcode &&
			    chan == fh->fh_key1 && tag == fh->fh_key2) {
				rcode = (*fh->fh_handler)(sc, fh->fh_handarg,
				    &pkt);
				break;
			}
		}
#ifdef FW_DEBUG
		if (fh == NULL)
			printf("fwohci_ir_input: no handler\n");
		else
			printf("fwohci_ir_input: rcode %d\n", rcode);
#endif
	}
	fwohci_buf_next(sc, fc);
	OHCI_SYNC_RX_DMA_WRITE(sc, fc->fc_ctx, OHCI_SUBREG_ContextControlSet,
	    OHCI_CTXCTL_WAKE);
}

/*
 * Asynchronous Transmit common routine.
 */
static int
fwohci_at_output(struct fwohci_softc *sc, struct fwohci_ctx *fc,
    struct fwohci_pkt *pkt)
{
	struct fwohci_buf *fb, *nfb;
	struct fwohci_desc *fd;
	struct iovec *iov;
	int i, ndesc;
	u_int32_t val;

#ifdef FW_DEBUG
	printf("fwohci_at_output: tcode 0x%x, hlen %d, dlen %d",
	    pkt->fp_tcode, pkt->fp_hlen, pkt->fp_dlen);
	for (i = 0; i < pkt->fp_hlen/4; i++)
		printf("%s%08x", i?" ":"\n\t", pkt->fp_hdr[i]);
	printf("$");
	for (ndesc = 0, iov = pkt->fp_iov; ndesc < pkt->fp_iovcnt; ndesc++, iov++) {
		for (i = 0; i < iov->iov_len; i++)
			printf("%s%02x", (i%32)?((i%4)?"":" "):"\n\t",
			    ((u_int8_t *)iov->iov_base)[i]);
		printf("$");
	}
	printf("\n");
#endif

	ndesc = 2 + pkt->fp_iovcnt;
	if (ndesc > 8)
		return ENOBUFS;

	fb = TAILQ_FIRST(&fc->fc_buf);
	if (fb == NULL)
		return ENOBUFS;
	for (i = 1, fb = TAILQ_FIRST(&fc->fc_buf); i < ndesc; i++, fb = nfb) {
		nfb = TAILQ_NEXT(fb, fb_list);
		if (nfb == NULL)
			return ENOBUFS;
		if (nfb->fb_desc != fb->fb_desc + 1) {
			while ((fb = TAILQ_FIRST(&fc->fc_buf)) != nfb) {
				TAILQ_REMOVE(&fc->fc_buf, fb, fb_list);
				TAILQ_INSERT_TAIL(&fc->fc_buf, fb, fb_list);
			}
			break;
		}
	}

	fb = TAILQ_FIRST(&fc->fc_buf);
	fd = fb->fb_desc;
	fd->fd_flags = OHCI_DESC_IMMED;
	fd->fd_reqcount = pkt->fp_hlen;
	fd->fd_data = 0;
	fd->fd_branch = 0;
	fd->fd_status = 0;
	if (fc->fc_ctx == OHCI_CTX_ASYNC_TX_RESPONSE) {
		i = 3;				/* XXX: 3 sec */
		val = OHCI_CSR_READ(sc, OHCI_REG_IsochronousCycleTimer);
		fd->fd_timestamp = ((val >> 12) & 0x1fff) |
		    ((((val >> 25) + i) & 0x7) << 13);
	} else
		fd->fd_timestamp = 0;
	fb = TAILQ_NEXT(fb, fb_list);
	memcpy(fb->fb_desc, pkt->fp_hdr, pkt->fp_hlen);
	for (i = 0, iov = pkt->fp_iov; i < pkt->fp_iovcnt; i++, iov++) {
		fb = TAILQ_NEXT(fb, fb_list);
		memcpy(fb->fb_buf, iov->iov_base, iov->iov_len); /*XXX*/
		fd = fb->fb_desc;
		fd->fd_flags = 0;
		fd->fd_reqcount = iov->iov_len;
		fd->fd_data = fb->fb_dmamap->dm_segs[0].ds_addr;
		fd->fd_branch = 0;
		fd->fd_status = 0;
		fd->fd_timestamp = 0;
	}
	fd->fd_flags |= OHCI_DESC_LAST | OHCI_DESC_BRANCH;
	fd->fd_flags |= OHCI_DESC_INTR_ALWAYS;
	/* hang mbuf on the last buffer */
	fb->fb_m = pkt->fp_m;
	fb->fb_callback = pkt->fp_callback;

	fb = TAILQ_FIRST(&fc->fc_buf);
#ifdef FW_DEBUG
	printf("fwohci_at_output: desc %d", fb->fb_desc - (struct fwohci_desc *)sc->sc_desc);
	for (i = 0; i < ndesc * 4; i++)
		printf("%s%08x", i&7?" ":"\n\t", ((u_int32_t *)fb->fb_desc)[i]);
	printf("\n");
#endif

	val = OHCI_ASYNC_DMA_READ(sc, fc->fc_ctx,
	    OHCI_SUBREG_ContextControlClear);

	if (val & OHCI_CTXCTL_RUN) {
		if (fc->fc_branch == NULL) {
			OHCI_ASYNC_DMA_WRITE(sc, fc->fc_ctx,
			    OHCI_SUBREG_ContextControlClear, OHCI_CTXCTL_RUN);
			goto run;
		}
		*fc->fc_branch = fb->fb_daddr | ndesc;
		if ((val & OHCI_CTXCTL_ACTIVE) == 0)
			OHCI_ASYNC_DMA_WRITE(sc, fc->fc_ctx,
			    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_WAKE);
	} else {
  run:
		OHCI_ASYNC_DMA_WRITE(sc, fc->fc_ctx,
		    OHCI_SUBREG_CommandPtr, fb->fb_daddr | ndesc);
		OHCI_ASYNC_DMA_WRITE(sc, fc->fc_ctx,
		    OHCI_SUBREG_ContextControlSet, OHCI_CTXCTL_RUN);
	}
	fc->fc_branch = &fd->fd_branch;

	for (i = 0; i < ndesc; i++) {
		fb = TAILQ_FIRST(&fc->fc_buf);
		TAILQ_REMOVE(&fc->fc_buf, fb, fb_list);
		TAILQ_INSERT_TAIL(&fc->fc_busy, fb, fb_list);
	}
	return 0;
}

static void
fwohci_at_done(struct fwohci_softc *sc, struct fwohci_ctx *fc)
{
	struct fwohci_buf *fb, *lfb;

	while ((fb = TAILQ_FIRST(&fc->fc_busy)) != NULL) {
		for (lfb = fb; lfb != NULL; lfb = TAILQ_NEXT(lfb, fb_list)) {
#ifdef FW_DEBUG
			printf("fwohci_at_done: desc %d, %08x %08x %08x %08x\n",
			    lfb->fb_desc - (struct fwohci_desc *)sc->sc_desc,
			    ((u_int32_t *)lfb->fb_desc)[0],
			    ((u_int32_t *)lfb->fb_desc)[1],
			    ((u_int32_t *)lfb->fb_desc)[2],
			    ((u_int32_t *)lfb->fb_desc)[3]);
#endif
			if (lfb->fb_desc->fd_flags & OHCI_DESC_LAST)
				break;
		}
		if (lfb == NULL) {
			printf("fwohci_at_done: last not found\n");
			break;
		}
		if (!(lfb->fb_desc->fd_status & OHCI_CTXCTL_ACTIVE))
			break;
		if (lfb->fb_desc->fd_flags & OHCI_DESC_IMMED)
			lfb = TAILQ_NEXT(lfb, fb_list);
		do {
			fb = TAILQ_FIRST(&fc->fc_busy);
			TAILQ_REMOVE(&fc->fc_busy, fb, fb_list);
			if (fb->fb_m != NULL) {
				if (fb->fb_callback != NULL) {
					(*fb->fb_callback)
					    (sc->sc_sc1394.sc1394_if, fb->fb_m);
					fb->fb_callback = NULL;
				} else {
					m_freem(fb->fb_m);
				}
				fb->fb_m = NULL;
			}
			TAILQ_INSERT_TAIL(&fc->fc_buf, fb, fb_list);
		} while (fb != lfb);
	}
}

/*
 * Asynchronous Transmit Reponse -- in response of request packet.
 */
static void
fwohci_atrs_output(struct fwohci_softc *sc, int rcode, struct fwohci_pkt *req,
    struct fwohci_pkt *res)
{
	int i;

	if (((*req->fp_trail & 0x001f0000) >> 16) !=
	    OHCI_CTXCTL_EVENT_ACK_PENDING)
		return;

	res->fp_hdr[0] = (req->fp_hdr[0] & 0x0000fc00) | 0x00000100;
	res->fp_hdr[1] = (req->fp_hdr[1] & 0xffff0000) | (rcode << 12);
	switch (req->fp_tcode) {
	case IEEE1394_TCODE_WRITE_REQ_QUAD:
	case IEEE1394_TCODE_WRITE_REQ_BLOCK:
		res->fp_tcode = IEEE1394_TCODE_WRITE_RESP;
		res->fp_hlen = 12;
		break;
	case IEEE1394_TCODE_READ_REQ_QUAD:
		res->fp_tcode = IEEE1394_TCODE_READ_RESP_QUAD;
		res->fp_hlen = 16;
		res->fp_dlen = 0;
		if (res->fp_iovcnt == 1 && res->fp_iov[0].iov_len == 4)
			res->fp_hdr[3] =
			    *(u_int32_t *)res->fp_iov[0].iov_base;
		res->fp_iovcnt = 0;
		break;
	case IEEE1394_TCODE_READ_REQ_BLOCK:
	case IEEE1394_TCODE_LOCK_REQ:
		if (req->fp_tcode == IEEE1394_TCODE_LOCK_REQ)
			res->fp_tcode = IEEE1394_TCODE_LOCK_RESP;
		else
			res->fp_tcode = IEEE1394_TCODE_READ_RESP_BLOCK;
		res->fp_hlen = 16;
		res->fp_dlen = 0;
		for (i = 0; i < res->fp_iovcnt; i++)
			res->fp_dlen += res->fp_iov[i].iov_len;
		res->fp_hdr[3] = res->fp_dlen << 16;
		break;
	}
	res->fp_hdr[0] |= (res->fp_tcode << 4);
	fwohci_at_output(sc, sc->sc_ctx_atrs, res);
}

/*
 * APPLICATION LAYER SERVICES
 */

/*
 * Initialization for Configuration ROM (no DMA context)
 */

#define	CFR_MAXUNIT		20

struct configromctx {
	u_int32_t	*ptr;
	int		curunit;
	struct {
		u_int32_t	*start;
		int		length;
		u_int32_t	*refer;
		int		refunit;
	} unit[CFR_MAXUNIT];
};

#define	CFR_PUT_DATA4(cfr, d1, d2, d3, d4)				\
	(*(cfr)->ptr++ = (((d1)<<24) | ((d2)<<16) | ((d3)<<8) | (d4)))

#define	CFR_PUT_DATA1(cfr, d)	(*(cfr)->ptr++ = (d))

#define	CFR_PUT_VALUE(cfr, key, d)	(*(cfr)->ptr++ = ((key)<<24) | (d))

#define	CFR_PUT_CRC(cfr, n)						\
	(*(cfr)->unit[n].start = ((cfr)->unit[n].length << 16) |	\
	    fwohci_crc16((cfr)->unit[n].start + 1, (cfr)->unit[n].length))

#define	CFR_START_UNIT(cfr, n)						\
do {									\
	if ((cfr)->unit[n].refer != NULL) {				\
		*(cfr)->unit[n].refer |=				\
		    (cfr)->ptr - (cfr)->unit[n].refer;			\
		CFR_PUT_CRC(cfr, (cfr)->unit[n].refunit);		\
	}								\
	(cfr)->curunit = (n);						\
	(cfr)->unit[n].start = (cfr)->ptr++;				\
} while (0 /* CONSTCOND */)

#define	CFR_PUT_REFER(cfr, key, n)					\
do {									\
	(cfr)->unit[n].refer = (cfr)->ptr;				\
	(cfr)->unit[n].refunit = (cfr)->curunit;			\
	*(cfr)->ptr++ = (key) << 24;					\
} while (0 /* CONSTCOND */)

#define	CFR_END_UNIT(cfr)						\
do {									\
	(cfr)->unit[(cfr)->curunit].length = (cfr)->ptr -		\
	    ((cfr)->unit[(cfr)->curunit].start + 1);			\
	CFR_PUT_CRC(cfr, (cfr)->curunit);				\
} while (0 /* CONSTCOND */)

static u_int16_t
fwohci_crc16(u_int32_t *ptr, int len)
{
	int shift;
	u_int32_t crc, sum, data;

	crc = 0;
	while (len-- > 0) {
		data = *ptr++;
		for (shift = 28; shift >= 0; shift -= 4) {
			sum = ((crc >> 12) ^ (data >> shift)) & 0x000f;
			crc = (crc << 4) ^ (sum << 12) ^ (sum << 5) ^ sum;
		}
		crc &= 0xffff;
	}
	return crc;
}

static void
fwohci_configrom_init(struct fwohci_softc *sc)
{
	int i;
	struct fwohci_buf *fb;
	u_int32_t *hdr;
	struct configromctx cfr;

	fb = &sc->sc_buf_cnfrom;
	memset(&cfr, 0, sizeof(cfr));
	cfr.ptr = hdr = (u_int32_t *)fb->fb_buf;

	/* headers */
	CFR_START_UNIT(&cfr, 0);
	CFR_PUT_DATA1(&cfr, OHCI_CSR_READ(sc, OHCI_REG_BusId));
	CFR_PUT_DATA1(&cfr, OHCI_CSR_READ(sc, OHCI_REG_BusOptions));
	CFR_PUT_DATA1(&cfr, OHCI_CSR_READ(sc, OHCI_REG_GUIDHi));
	CFR_PUT_DATA1(&cfr, OHCI_CSR_READ(sc, OHCI_REG_GUIDLo));
	CFR_END_UNIT(&cfr);
	/* copy info_length from crc_length */
	*hdr |= (*hdr & 0x00ff0000) << 8;
	OHCI_CSR_WRITE(sc, OHCI_REG_ConfigROMhdr, *hdr);

	/* root directory */
	CFR_START_UNIT(&cfr, 1);
	CFR_PUT_VALUE(&cfr, 0x03, 0x00005e);	/* vendor id */
	CFR_PUT_REFER(&cfr, 0x81, 2);		/* textual descriptor offset */
	CFR_PUT_VALUE(&cfr, 0x0c, 0x0083c0);	/* node capability */
						/* spt,64,fix,lst,drq */
#ifdef INET
	CFR_PUT_REFER(&cfr, 0xd1, 3);		/* IPv4 unit directory */
#endif /* INET */
#ifdef INET6
	CFR_PUT_REFER(&cfr, 0xd1, 4);		/* IPv6 unit directory */
#endif /* INET6 */
	CFR_END_UNIT(&cfr);

	CFR_START_UNIT(&cfr, 2);
	CFR_PUT_VALUE(&cfr, 0, 0);		/* textual descriptor */
	CFR_PUT_DATA1(&cfr, 0);			/* minimal ASCII */
	CFR_PUT_DATA4(&cfr, 'N', 'e', 't', 'B');
	CFR_PUT_DATA4(&cfr, 'S', 'D', 0x00, 0x00);
	CFR_END_UNIT(&cfr);

#ifdef INET
	/* IPv4 unit directory */
	CFR_START_UNIT(&cfr, 3);
	CFR_PUT_VALUE(&cfr, 0x12, 0x00005e);	/* unit spec id */
	CFR_PUT_REFER(&cfr, 0x81, 6);		/* textual descriptor offset */
	CFR_PUT_VALUE(&cfr, 0x13, 0x000001);	/* unit sw version */
	CFR_PUT_REFER(&cfr, 0x81, 7);		/* textual descriptor offset */
	CFR_END_UNIT(&cfr);

	CFR_START_UNIT(&cfr, 6);
	CFR_PUT_VALUE(&cfr, 0, 0);		/* textual descriptor */
	CFR_PUT_DATA1(&cfr, 0);			/* minimal ASCII */
	CFR_PUT_DATA4(&cfr, 'I', 'A', 'N', 'A');
	CFR_END_UNIT(&cfr);

	CFR_START_UNIT(&cfr, 7);
	CFR_PUT_VALUE(&cfr, 0, 0);		/* textual descriptor */
	CFR_PUT_DATA1(&cfr, 0);			/* minimal ASCII */
	CFR_PUT_DATA4(&cfr, 'I', 'P', 'v', '4');
	CFR_END_UNIT(&cfr);
#endif /* INET */

#ifdef INET6
	/* IPv6 unit directory */
	CFR_START_UNIT(&cfr, 4);
	CFR_PUT_VALUE(&cfr, 0x12, 0x00005e);	/* unit spec id */
	CFR_PUT_REFER(&cfr, 0x81, 8);		/* textual descriptor offset */
	CFR_PUT_VALUE(&cfr, 0x13, 0x000001);	/* unit sw version */
	CFR_PUT_REFER(&cfr, 0x81, 9);		/* textual descriptor offset */
	CFR_END_UNIT(&cfr);

	CFR_START_UNIT(&cfr, 8);
	CFR_PUT_VALUE(&cfr, 0, 0);		/* textual descriptor */
	CFR_PUT_DATA1(&cfr, 0);			/* minimal ASCII */
	CFR_PUT_DATA4(&cfr, 'I', 'A', 'N', 'A');
	CFR_END_UNIT(&cfr);

	CFR_START_UNIT(&cfr, 9);
	CFR_PUT_VALUE(&cfr, 0, 0);		/* textual descriptor */
	CFR_PUT_DATA1(&cfr, 0);
	CFR_PUT_DATA4(&cfr, 'I', 'P', 'v', '6');
	CFR_END_UNIT(&cfr);
#endif /* INET6 */

#ifdef FW_DEBUG
	printf("%s: Config ROM:", sc->sc_sc1394.sc1394_dev.dv_xname);
	for (i = 0; i < cfr.ptr - hdr; i++)
		printf("%s%08x", i&7?" ":"\n    ", hdr[i]);
	printf("\n");
#endif /* FW_DEBUG */

	/*
	 * Make network byte order for DMA
	 */
	for (i = 0; i < cfr.ptr - hdr; i++)
		NTOHL(hdr[i]);
	bus_dmamap_sync(sc->sc_dmat, fb->fb_dmamap, 0,
	    (caddr_t)cfr.ptr - fb->fb_buf, BUS_DMASYNC_PREWRITE);

	OHCI_CSR_WRITE(sc, OHCI_REG_ConfigROMmap,
	    fb->fb_dmamap->dm_segs[0].ds_addr);
	OHCI_CSR_WRITE(sc, OHCI_REG_HCControlSet, OHCI_HCControl_BIBImageValid);
}

/*
 * SelfID buffer (no DMA context)
 */
static void
fwohci_selfid_init(struct fwohci_softc *sc)
{
	struct fwohci_buf *fb;

	fb = &sc->sc_buf_selfid;
	memset(fb->fb_buf, 0, OHCI_PAGE_SIZE);
	bus_dmamap_sync(sc->sc_dmat, fb->fb_dmamap, 0, OHCI_PAGE_SIZE,
	    BUS_DMASYNC_PREREAD);

	OHCI_CSR_WRITE(sc, OHCI_REG_SelfIDBuffer,
	    fb->fb_dmamap->dm_segs[0].ds_addr);
}

static void
fwohci_selfid_input(struct fwohci_softc *sc)
{
	int i;
	u_int32_t count, val;
	u_int32_t *buf;

	val = OHCI_CSR_READ(sc, OHCI_REG_SelfIDCount);
	if (val & OHCI_SelfID_Error) {
		printf("%s: SelfID Error\n", sc->sc_sc1394.sc1394_dev.dv_xname);
		return;
	}
	count = (val & OHCI_SelfID_Size_MASK) >> OHCI_SelfID_Size_BITPOS;

	bus_dmamap_sync(sc->sc_dmat, sc->sc_buf_selfid.fb_dmamap,
	    0, count << 2, BUS_DMASYNC_POSTREAD);

	buf = (u_int32_t *)sc->sc_buf_selfid.fb_buf;
	if ((val & OHCI_SelfID_Gen_MASK) != (*buf & OHCI_SelfID_Gen_MASK)) {
		printf("%s: SelfID Gen mismatch (%d, %d)\n",
		    sc->sc_sc1394.sc1394_dev.dv_xname,
		    (val & OHCI_SelfID_Gen_MASK) >> OHCI_SelfID_Gen_BITPOS,
		    (*buf & OHCI_SelfID_Gen_MASK) >> OHCI_SelfID_Gen_BITPOS);
		return;
	}

#ifdef FW_DEBUG
	printf("\n%s: SelfID:", sc->sc_sc1394.sc1394_dev.dv_xname);
	for (i = 0; i < count; i++)
		printf("%s%08x", i&7?" ":"\n    ", buf[i]);
	printf("\n");
#endif /* FW_DEBUG */

	sc->sc_irmid = IEEE1394_BCAST_PHY_ID;
	for (i = 1; i < count; i += 2) {
		if (buf[i] != ~buf[i + 1]) {
			printf("%s: SelfID corrupted (%d, 0x%08x, 0x%08x)\n",
			    sc->sc_sc1394.sc1394_dev.dv_xname, i,
			    buf[i], buf[i + 1]);
			return;
		}
		if (buf[i] & 0x00000001)
			continue;	/* more pkt */
		if (buf[i] & 0x00800000)
			continue;	/* external id */
		sc->sc_rootid = (buf[i] & 0x3f000000) >> 24;
		if ((buf[i] & 0x00400800) == 0x00400800)
			sc->sc_irmid = sc->sc_rootid;
	}
	val = OHCI_CSR_READ(sc, OHCI_REG_NodeId);
	if ((val & OHCI_NodeId_IDValid) == 0) {
		sc->sc_nodeid = IEEE1394_BCAST_PHY_ID;	/* invalid */
		return;
	}
	sc->sc_nodeid = val & 0xffff;
#ifdef FW_DEBUG
	printf("%s: nodeid=0x%04x(%d), rootid=%d, irmid=%d\n",
	    sc->sc_sc1394.sc1394_dev.dv_xname,
	    sc->sc_nodeid, sc->sc_nodeid & OHCI_NodeId_NodeNumber,
	    sc->sc_rootid, sc->sc_irmid);
#endif

	if ((sc->sc_nodeid & OHCI_NodeId_NodeNumber) > sc->sc_rootid)
		return;

	if ((sc->sc_nodeid & OHCI_NodeId_NodeNumber) == sc->sc_rootid)
		OHCI_CSR_WRITE(sc, OHCI_REG_LinkControlSet,
		    OHCI_LinkControl_CycleMaster);
	else
		OHCI_CSR_WRITE(sc, OHCI_REG_LinkControlClear,
		    OHCI_LinkControl_CycleMaster);
}


/*
 * some CSRs are handled by driver.
 */
static void
fwohci_csr_init(struct fwohci_softc *sc)
{
	int i;
	static u_int32_t csr[] = { 
	    CSR_STATE_CLEAR, CSR_STATE_SET, CSR_SB_CYCLE_TIME,
	    CSR_SB_BUS_TIME, CSR_SB_BUSY_TIMEOUT, CSR_SB_BUS_MANAGER_ID,
	    CSR_SB_CHANNEL_AVAILABLE_HI, CSR_SB_CHANNEL_AVAILABLE_LO,
	    CSR_SB_BROADCAST_CHANNEL
	};

	for (i = 0; i < sizeof(csr) / sizeof(csr[0]); i++) {
		fwohci_handler_set(sc, IEEE1394_TCODE_WRITE_REQ_QUAD,
		    CSR_BASE_HI, CSR_BASE_LO + csr[i], fwohci_csr_input, NULL);
		fwohci_handler_set(sc, IEEE1394_TCODE_READ_REQ_QUAD,
		    CSR_BASE_HI, CSR_BASE_LO + csr[i], fwohci_csr_input, NULL);
	}
	sc->sc_csr[CSR_SB_BROADCAST_CHANNEL] = 31;	/*XXX*/
}

static int
fwohci_csr_input(struct fwohci_softc *sc, void *arg, struct fwohci_pkt *pkt)
{
	struct fwohci_pkt res;
	u_int32_t reg;

	/*
	 * XXX need to do special functionality other than just r/w...
	 */
	reg = pkt->fp_hdr[2] - CSR_BASE_LO;

	if ((reg & 0x03) != 0) {
		/* alignment error */
		return IEEE1394_RCODE_ADDRESS_ERROR;
	}
	if (pkt->fp_tcode == IEEE1394_TCODE_WRITE_REQ_QUAD) {
#ifdef FW_DEBUG
		printf("fwohci_csr_input: CSR[0x%04x]: 0x%08x -> 0x%08x\n",
		    reg, *(u_int32_t *)(&sc->sc_csr[reg]),
		    ntohl(*(u_int32_t *)pkt->fp_iov[0].iov_base));
#endif
		*(u_int32_t *)&sc->sc_csr[reg] =
		    ntohl(*(u_int32_t *)pkt->fp_iov[0].iov_base);
	} else {
#ifdef FW_DEBUG
		printf("fwohci_csr_input: CSR[0x%04x]: 0x%08x\n",
		    reg, *(u_int32_t *)(&sc->sc_csr[reg]));
#endif
		res.fp_hdr[3] = htonl(*(u_int32_t *)&sc->sc_csr[reg]);
		res.fp_iov[0].iov_base = &res.fp_hdr[3];
		res.fp_iov[0].iov_len = 4;
		res.fp_iovcnt = 1;
		fwohci_atrs_output(sc, IEEE1394_RCODE_COMPLETE, pkt, &res);
		return -1;
	}
	return IEEE1394_RCODE_COMPLETE;
}

/*
 * Mapping between nodeid and unique ID (EUI-64).
 */
static void
fwohci_uid_collect(struct fwohci_softc *sc)
{
	int i;
	struct fwohci_uidtbl *fu;
	struct fwohci_pkt pkt;

	if (sc->sc_uidtbl != NULL)
		free(sc->sc_uidtbl, M_DEVBUF);
	sc->sc_uidtbl = malloc(sizeof(*fu) * (sc->sc_rootid + 1),
	    M_DEVBUF, M_NOWAIT);
	if (sc->sc_uidtbl == NULL)
		return;
	memset(sc->sc_uidtbl, 0, sizeof(*fu) * (sc->sc_rootid + 1));

	memset(&pkt, 0, sizeof(pkt));
	for (i = 0, fu = sc->sc_uidtbl; i <= sc->sc_rootid; i++, fu++) {
		if (i == (sc->sc_nodeid & OHCI_NodeId_NodeNumber)) {
			memcpy(fu->fu_hi.fu_uid, sc->sc_sc1394.sc1394_guid, 4);
			memcpy(fu->fu_lo.fu_uid, sc->sc_sc1394.sc1394_guid, 4);
			fu->fu_hi.fu_valid = fu->fu_lo.fu_valid = 1;
			continue;
		}
		fu->fu_hi.fu_valid = fu->fu_lo.fu_valid = 0;
		pkt.fp_tcode = IEEE1394_TCODE_READ_REQ_QUAD;
		pkt.fp_hlen = 12;
		pkt.fp_dlen = 0;
		pkt.fp_hdr[0] = 0x00000100 | (sc->sc_tlabel << 10) |
		    (pkt.fp_tcode << 4);
		pkt.fp_hdr[1] = ((0xffc0 | i) << 16) | CSR_BASE_HI;
		pkt.fp_hdr[2] = CSR_BASE_LO + CSR_CONFIG_ROM + 12;
		fwohci_handler_set(sc, IEEE1394_TCODE_READ_RESP_QUAD, i,
		    sc->sc_tlabel, fwohci_uid_input, &fu->fu_hi);
		sc->sc_tlabel = (sc->sc_tlabel + 1) & 0x3f;
		fwohci_at_output(sc, sc->sc_ctx_atrq, &pkt);

		pkt.fp_hdr[0] = 0x00000100 | (sc->sc_tlabel << 10) |
		    (pkt.fp_tcode << 4);
		pkt.fp_hdr[2] = CSR_BASE_LO + CSR_CONFIG_ROM + 16;
		fwohci_handler_set(sc, IEEE1394_TCODE_READ_RESP_QUAD, i,
		    sc->sc_tlabel, fwohci_uid_input, &fu->fu_lo);
		sc->sc_tlabel = (sc->sc_tlabel + 1) & 0x3f;
		fwohci_at_output(sc, sc->sc_ctx_atrq, &pkt);
	}
}

static int
fwohci_uid_input(struct fwohci_softc *sc, void *arg, struct fwohci_pkt *res)
{
	struct fwohci_uident *fu = arg;

	memcpy(fu->fu_uid, res->fp_iov[0].iov_base, 4);
	fu->fu_valid = 1;
#ifdef FW_DEBUG
	printf("fwohci_uid_input: %02x%02x%02x%02x\n",
	    fu->fu_uid[0], fu->fu_uid[1], fu->fu_uid[2], fu->fu_uid[3]);
#endif
	return 0;
}

static int
fwohci_uid_lookup(struct fwohci_softc *sc, u_int8_t *uid)
{
	struct fwohci_uidtbl *fu;
	int n;
	static const u_int8_t bcast[] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (memcmp(uid, bcast, sizeof(bcast)) == 0)
		return IEEE1394_BCAST_PHY_ID;
	fu = sc->sc_uidtbl;
	if (fu == NULL) {
		fwohci_uid_collect(sc); /* try to get */
		return -1;
	}
	for (n = 0; n <= sc->sc_rootid; n++, fu++) {
		if (fu->fu_hi.fu_valid && fu->fu_lo.fu_valid &&
		    memcmp(fu->fu_hi.fu_uid, uid, 4) == 0 &&
		    memcmp(fu->fu_lo.fu_uid, uid + 4, 4) == 0)
			break;
	}
	if (n > sc->sc_rootid) {
		fwohci_uid_collect(sc); /* try to get */
		return -1;
	}
	return n;
}

/*
 * functions to support network interface
 */
static int
fwohci_if_inreg(struct device *self, u_int32_t offhi, u_int32_t offlo,
    void (*handler)(struct device *, struct mbuf *))
{
	struct fwohci_softc *sc = (struct fwohci_softc *)self;

	fwohci_handler_set(sc, IEEE1394_TCODE_WRITE_REQ_BLOCK, offhi, offlo, 
	    fwohci_if_input, handler);
	fwohci_handler_set(sc, IEEE1394_TCODE_STREAM_DATA,
	    sc->sc_csr[CSR_SB_BROADCAST_CHANNEL] & OHCI_NodeId_NodeNumber,
	    IEEE1394_TAG_GASP, fwohci_if_input, handler);
	return 0;
}

static int
fwohci_if_input(struct fwohci_softc *sc, void *arg, struct fwohci_pkt *pkt)
{
	int n, len;
	struct mbuf *m;
	struct iovec *iov;
	void (*handler)(struct device *, struct mbuf *) = arg;

#ifdef FW_DEBUG
	{ int i;
	printf("fwohci_if_input: tcode=0x%x, dlen=%d",
	    pkt->fp_tcode, pkt->fp_dlen);
	for (i = 0; i < pkt->fp_hlen/4; i++)
		printf("%s%08x", i?" ":"\n\t", pkt->fp_hdr[i]);
	printf("$");
	for (n = 0, len = pkt->fp_dlen; len > 0; len -= i, n++) {
		iov = &pkt->fp_iov[n];
		for (i = 0; i < iov->iov_len; i++)
			printf("%s%02x", (i%32)?((i%4)?"":" "):"\n\t",
			    ((u_int8_t *)iov->iov_base)[i]);
		printf("$");
	}
	printf("\n");
	}
#endif /* FW_DEBUG */
	len = pkt->fp_dlen;
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return IEEE1394_RCODE_COMPLETE;
	if (pkt->fp_tcode == IEEE1394_TCODE_STREAM_DATA)
		m->m_flags |= M_BCAST;
	m->m_pkthdr.rcvif = NULL;	/* set in child */
	m->m_pkthdr.len = len;
	m->m_len = 0;
	if (len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			return IEEE1394_RCODE_COMPLETE;
		}
	}
	/*
	 * We may use receive buffer by external mbuf instead of copy here.
	 * But asynchronous receive buffer must be operate in buffer fill
	 * mode, so that each receive buffer will shared by multiple mbufs.
	 * If upper layer doesn't free mbuf soon, e.g. application program
	 * is suspended, buffer must be reallocated.
	 * Isochronous buffer must be operate in packet buffer mode, and
	 * it is easy to map receive buffer to external mbuf.  But it is
	 * used for broadcast/multicast only, and is expected not so
	 * performance sensitive for now.
	 * XXX: The performance may be important for multicast case,
	 * so we should revisit here later.
	 *						-- onoe
	 */
	n = 0;
	iov = pkt->fp_iov;
	while (len > 0) {
		memcpy(mtod(m, caddr_t) + m->m_len, iov->iov_base,
		    iov->iov_len);
	        m->m_len += iov->iov_len;
	        len -= iov->iov_len;
		iov++;
	}
	(*handler)(sc->sc_sc1394.sc1394_if, m);
	return IEEE1394_RCODE_COMPLETE;
}

static int
fwohci_if_output(struct device *self, struct mbuf *m0,
    void (*callback)(struct device *, struct mbuf *))
{
	struct fwohci_softc *sc = (struct fwohci_softc *)self;
	struct mbuf *m;
	struct fwohci_pkt pkt;
	struct iovec *iov;
	u_int8_t *p;
	int n;
	int error;

	memset(&pkt, 0, sizeof(pkt));
	if (m0->m_flags & (M_BCAST|M_MCAST)) {
		m_adj(m0, 8);
		/* construct GASP header */
		p = mtod(m0, u_int8_t *);
		p[0] = sc->sc_nodeid >> 8;
		p[1] = sc->sc_nodeid & 0xff;
		p[2] = 0x00; p[3] = 0x00; p[4] = 0x5e;
		p[5] = 0x00; p[6] = 0x00; p[7] = 0x01;
		pkt.fp_tcode = IEEE1394_TCODE_STREAM_DATA;
		pkt.fp_hlen = 8;
		pkt.fp_hdr[0] = (IEEE1394_TAG_GASP << 14) |
		    ((sc->sc_csr[CSR_SB_BROADCAST_CHANNEL] &
		    OHCI_NodeId_NodeNumber) << 8);
		pkt.fp_hdr[1] = m0->m_pkthdr.len << 16;
	} else {
		p = mtod(m0, u_int8_t *);
		m_adj(m0, 16);
		n = fwohci_uid_lookup(sc, p);
		if (n < 0) {
			printf("fwohci_if_output: nodeid unknown: %08x%08x\n",
			    htonl(((u_int32_t *)p)[0]),
			    htonl(((u_int32_t *)p)[1]));
			error = EHOSTUNREACH;
			goto end;
		}
		if (n == (sc->sc_nodeid & OHCI_NodeId_NodeNumber)) {
			/* should not come here */
			error = EIO;
			goto end;
		}
		pkt.fp_tcode = IEEE1394_TCODE_WRITE_REQ_BLOCK;
		pkt.fp_hlen = 16;
		pkt.fp_hdr[0] = 0x00800100 | (sc->sc_tlabel << 10) |
		    (p[9] << 16);
		pkt.fp_hdr[1] =
		    (((sc->sc_nodeid & OHCI_NodeId_BusNumber) | n) << 16) |
		    (p[10] << 8) | p[11];
		pkt.fp_hdr[2] = (p[12]<<24) | (p[13]<<16) | (p[14]<<8) | p[15];
		pkt.fp_hdr[3] = m0->m_pkthdr.len << 16;
		sc->sc_tlabel = (sc->sc_tlabel + 1) & 0x3f;
	}
	pkt.fp_hdr[0] |= (pkt.fp_tcode << 4);
	pkt.fp_dlen = m0->m_pkthdr.len;
	for (m = m0; m != NULL; m = m->m_next) {
		iov = &pkt.fp_iov[pkt.fp_iovcnt++]; 
		iov->iov_base = mtod(m, caddr_t);
		iov->iov_len = m->m_len;
	}
	pkt.fp_m = m0;
	pkt.fp_callback = callback;
	error = fwohci_at_output(sc, sc->sc_ctx_atrq, &pkt);
  end:
	if (error) {
		if (callback)
			(*callback)(sc->sc_sc1394.sc1394_if, m0);
		else
			m_freem(m0);
	}
	return error;
}
