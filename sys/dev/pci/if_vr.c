/*	$NetBSD: if_vr.c,v 1.9 1999/02/05 01:10:30 thorpej Exp $	*/

/*
 * Copyright (c) 1997, 1998
 *	Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
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
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$FreeBSD: if_vr.c,v 1.7 1999/01/10 18:51:49 wpaul Exp $
 */

/*
 * VIA Rhine fast ethernet PCI NIC driver
 *
 * Supports various network adapters based on the VIA Rhine
 * and Rhine II PCI controllers, including the D-Link DFE530TX.
 * Datasheets are available at http://www.via.com.tw.
 *
 * Written by Bill Paul <wpaul@ctr.columbia.edu>
 * Electrical Engineering Department
 * Columbia University, New York City
 */

/*
 * The VIA Rhine controllers are similar in some respects to the
 * the DEC tulip chips, except less complicated. The controller
 * uses an MII bus and an external physical layer interface. The
 * receiver has a one entry perfect filter and a 64-bit hash table
 * multicast filter. Transmit and receive descriptors are similar
 * to the tulip.
 *
 * The Rhine has a serious flaw in its transmit DMA mechanism:
 * transmit buffers must be longword aligned. Unfortunately,
 * FreeBSD doesn't guarantee that mbufs will be filled in starting
 * at longword boundaries, so we have to do a buffer copy before
 * transmission.
 */

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/device.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_ether.h>

#if defined(INET)
#include <netinet/in.h>
#include <netinet/if_inarp.h>
#endif

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <vm/vm.h>		/* for vtophys */

#include <machine/bus.h>
#include <machine/intr.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#include <dev/pci/if_vrreg.h>

#if defined(__NetBSD__) && defined(__alpha__)
/* XXX XXX NEED REAL DMA MAPPING SUPPORT XXX XXX */
#undef vtophys
#define	vtophys(va)	alpha_XXX_dmamap((vaddr_t)(va))
#endif

#define	VR_USEIOSPACE

/* #define	VR_BACKGROUND_AUTONEG */

#define	ETHER_CRC_LEN	4	/* XXX Should be in a common header. */

/*
 * Various supported device vendors/types and their names.
 */
static struct vr_type {
	pci_vendor_id_t		vr_vid;
	pci_product_id_t	vr_did;
	const char		*vr_name;
} vr_devs[] = {
	{ PCI_VENDOR_VIATECH, PCI_PRODUCT_VIATECH_VT3043,
		"VIA VT3043 Rhine I 10/100BaseTX" },
	{ PCI_VENDOR_VIATECH, PCI_PRODUCT_VIATECH_VT86C100A,
		"VIA VT86C100A Rhine II 10/100BaseTX" },
	{ 0, 0, NULL }
};

/*
 * Various supported PHY vendors/types and their names. Note that
 * this driver will work with pretty much any MII-compliant PHY,
 * so failure to positively identify the chip is not a fatal error.
 */

static struct vr_type vr_phys[] = {
	{ TI_PHY_VENDORID, TI_PHY_10BT, "<TI ThunderLAN 10BT (internal)>" },
	{ TI_PHY_VENDORID, TI_PHY_100VGPMI, "<TI TNETE211 100VG Any-LAN>" },
	{ NS_PHY_VENDORID, NS_PHY_83840A, "<National Semiconductor DP83840A>"},
	{ LEVEL1_PHY_VENDORID, LEVEL1_PHY_LXT970, "<Level 1 LXT970>" },
	{ INTEL_PHY_VENDORID, INTEL_PHY_82555, "<Intel 82555>" },
	{ SEEQ_PHY_VENDORID, SEEQ_PHY_80220, "<SEEQ 80220>" },
	{ 0, 0, "<MII-compliant physical interface>" }
};

struct vr_mii_frame {
	u_int8_t		mii_stdelim;
	u_int8_t		mii_opcode;
	u_int8_t		mii_phyaddr;
	u_int8_t		mii_regaddr;
	u_int8_t		mii_turnaround;
	u_int16_t		mii_data;
};

/*
 * MII constants
 */
#define	VR_MII_STARTDELIM	0x01
#define	VR_MII_READOP		0x02
#define	VR_MII_WRITEOP		0x01
#define	VR_MII_TURNAROUND	0x02

#define	VR_FLAG_FORCEDELAY	1
#define	VR_FLAG_SCHEDDELAY	2
#define	VR_FLAG_DELAYTIMEO	3

struct vr_list_data {
	struct vr_desc		vr_rx_list[VR_RX_LIST_CNT];
	struct vr_desc		vr_tx_list[VR_TX_LIST_CNT];
};

struct vr_chain {
	struct vr_desc		*vr_ptr;
	struct mbuf		*vr_mbuf;
	struct vr_chain		*vr_nextdesc;
};

struct vr_chain_onefrag {
	struct vr_desc		*vr_ptr;
	struct mbuf		*vr_mbuf;
	struct vr_chain_onefrag	*vr_nextdesc;
};

struct vr_chain_data {
	struct vr_chain_onefrag	vr_rx_chain[VR_RX_LIST_CNT];
	struct vr_chain		vr_tx_chain[VR_TX_LIST_CNT];

	struct vr_chain_onefrag	*vr_rx_head;

	struct vr_chain		*vr_tx_head;
	struct vr_chain		*vr_tx_tail;
	struct vr_chain		*vr_tx_free;
};

struct vr_softc {
	struct device		vr_dev;
	void			*vr_ih;
	void			*vr_ats;
	bus_space_tag_t		vr_bustag;
	bus_space_handle_t	vr_bushandle;
	pci_chipset_tag_t	vr_pc;
	struct ethercom		vr_ec;
	u_int8_t 		vr_enaddr[ETHER_ADDR_LEN];
	struct ifmedia		ifmedia;	/* media info */
	bus_space_handle_t	vr_bhandle;	/* bus space handle */
	bus_space_tag_t		vr_btag;	/* bus space tag */
	struct vr_type		*vr_info;	/* Rhine adapter info */
	struct vr_type		*vr_pinfo;	/* phy info */
	u_int8_t		vr_unit;	/* interface number */
	u_int8_t		vr_type;
	u_int8_t		vr_phy_addr;	/* PHY address */
	u_int8_t		vr_tx_pend;	/* TX pending */
	u_int8_t		vr_want_auto;
	u_int8_t		vr_autoneg;
	caddr_t			vr_ldata_ptr;
	struct vr_list_data	*vr_ldata;
	struct vr_chain_data	vr_cdata;
};

/*
 * register space access macros
 */
#define	CSR_WRITE_4(sc, reg, val)	\
	bus_space_write_4(sc->vr_btag, sc->vr_bhandle, reg, val)
#define	CSR_WRITE_2(sc, reg, val)	\
	bus_space_write_2(sc->vr_btag, sc->vr_bhandle, reg, val)
#define	CSR_WRITE_1(sc, reg, val)	\
	bus_space_write_1(sc->vr_btag, sc->vr_bhandle, reg, val)

#define	CSR_READ_4(sc, reg)		\
	bus_space_read_4(sc->vr_btag, sc->vr_bhandle, reg)
#define	CSR_READ_2(sc, reg)		\
	bus_space_read_2(sc->vr_btag, sc->vr_bhandle, reg)
#define	CSR_READ_1(sc, reg)		\
	bus_space_read_1(sc->vr_btag, sc->vr_bhandle, reg)

#define	VR_TIMEOUT		1000

static int vr_newbuf		__P((struct vr_softc *,
						struct vr_chain_onefrag *));
static int vr_encap		__P((struct vr_softc *, struct vr_chain *,
						struct mbuf *));

static void vr_rxeof		__P((struct vr_softc *));
static void vr_rxeoc		__P((struct vr_softc *));
static void vr_txeof		__P((struct vr_softc *));
static void vr_txeoc		__P((struct vr_softc *));
static void vr_intr		__P((void *));
static void vr_start		__P((struct ifnet *));
static int vr_ioctl		__P((struct ifnet *, u_long, caddr_t));
static void vr_init		__P((void *));
static void vr_stop		__P((struct vr_softc *));
static void vr_watchdog		__P((struct ifnet *));
static int vr_ifmedia_upd	__P((struct ifnet *));
static void vr_ifmedia_sts	__P((struct ifnet *, struct ifmediareq *));

static void vr_mii_sync		__P((struct vr_softc *));
static void vr_mii_send		__P((struct vr_softc *, u_int32_t, int));
static int vr_mii_readreg	__P((struct vr_softc *, struct vr_mii_frame *));
static int vr_mii_writereg	__P((struct vr_softc *, struct vr_mii_frame *));
static u_int16_t vr_phy_readreg	__P((struct vr_softc *, int));
static void vr_phy_writereg	__P((struct vr_softc *, u_int16_t, u_int16_t));

static void vr_autoneg_xmit	__P((struct vr_softc *));
static void vr_autoneg_mii	__P((struct vr_softc *, int, int));
static void vr_setmode_mii	__P((struct vr_softc *, int));
static void vr_getmode_mii	__P((struct vr_softc *));
static void vr_setcfg		__P((struct vr_softc *, u_int16_t));
static u_int8_t vr_calchash	__P((u_int8_t *));
static void vr_setmulti		__P((struct vr_softc *));
static void vr_reset		__P((struct vr_softc *));
static int vr_list_rx_init	__P((struct vr_softc *));
static int vr_list_tx_init	__P((struct vr_softc *));

#define	VR_SETBIT(sc, reg, x)				\
	CSR_WRITE_1(sc, reg,				\
		CSR_READ_1(sc, reg) | x)

#define	VR_CLRBIT(sc, reg, x)				\
	CSR_WRITE_1(sc, reg,				\
		CSR_READ_1(sc, reg) & ~x)

#define	VR_SETBIT16(sc, reg, x)				\
	CSR_WRITE_2(sc, reg,				\
		CSR_READ_2(sc, reg) | x)

#define	VR_CLRBIT16(sc, reg, x)				\
	CSR_WRITE_2(sc, reg,				\
		CSR_READ_2(sc, reg) & ~x)

#define	VR_SETBIT32(sc, reg, x)				\
	CSR_WRITE_4(sc, reg,				\
		CSR_READ_4(sc, reg) | x)

#define	VR_CLRBIT32(sc, reg, x)				\
	CSR_WRITE_4(sc, reg,				\
		CSR_READ_4(sc, reg) & ~x)

#define	SIO_SET(x)					\
	CSR_WRITE_1(sc, VR_MIICMD,			\
		CSR_READ_1(sc, VR_MIICMD) | x)

#define	SIO_CLR(x)					\
	CSR_WRITE_1(sc, VR_MIICMD,			\
		CSR_READ_1(sc, VR_MIICMD) & ~x)

/*
 * Sync the PHYs by setting data bit and strobing the clock 32 times.
 */
static void vr_mii_sync(sc)
	struct vr_softc		*sc;
{
	register int		i;

	SIO_SET(VR_MIICMD_DIR|VR_MIICMD_DATAOUT);

	for (i = 0; i < 32; i++) {
		SIO_SET(VR_MIICMD_CLK);
		DELAY(1);
		SIO_CLR(VR_MIICMD_CLK);
		DELAY(1);
	}

	return;
}

/*
 * Clock a series of bits through the MII.
 */
static void vr_mii_send(sc, bits, cnt)
	struct vr_softc		*sc;
	u_int32_t		bits;
	int			cnt;
{
	int			i;

	SIO_CLR(VR_MIICMD_CLK);

	for (i = (0x1 << (cnt - 1)); i; i >>= 1) {
		if (bits & i) {
			SIO_SET(VR_MIICMD_DATAOUT);
		} else {
			SIO_CLR(VR_MIICMD_DATAOUT);
		}
		DELAY(1);
		SIO_CLR(VR_MIICMD_CLK);
		DELAY(1);
		SIO_SET(VR_MIICMD_CLK);
	}
}

/*
 * Read an PHY register through the MII.
 */
static int vr_mii_readreg(sc, frame)
	struct vr_softc		*sc;
	struct vr_mii_frame	*frame;

{
	int			i, ack, s;

	s = splimp();

	/*
	 * Set up frame for RX.
	 */
	frame->mii_stdelim = VR_MII_STARTDELIM;
	frame->mii_opcode = VR_MII_READOP;
	frame->mii_turnaround = 0;
	frame->mii_data = 0;

	CSR_WRITE_1(sc, VR_MIICMD, 0);
	VR_SETBIT(sc, VR_MIICMD, VR_MIICMD_DIRECTPGM);

	/*
	 * Turn on data xmit.
	 */
	SIO_SET(VR_MIICMD_DIR);

	vr_mii_sync(sc);

	/*
	 * Send command/address info.
	 */
	vr_mii_send(sc, frame->mii_stdelim, 2);
	vr_mii_send(sc, frame->mii_opcode, 2);
	vr_mii_send(sc, frame->mii_phyaddr, 5);
	vr_mii_send(sc, frame->mii_regaddr, 5);

	/* Idle bit */
	SIO_CLR((VR_MIICMD_CLK|VR_MIICMD_DATAOUT));
	DELAY(1);
	SIO_SET(VR_MIICMD_CLK);
	DELAY(1);

	/* Turn off xmit. */
	SIO_CLR(VR_MIICMD_DIR);

	/* Check for ack */
	SIO_CLR(VR_MIICMD_CLK);
	DELAY(1);
	SIO_SET(VR_MIICMD_CLK);
	DELAY(1);
	ack = CSR_READ_4(sc, VR_MIICMD) & VR_MIICMD_DATAIN;

	/*
	 * Now try reading data bits. If the ack failed, we still
	 * need to clock through 16 cycles to keep the PHY(s) in sync.
	 */
	if (ack) {
		for (i = 0; i < 16; i++) {
			SIO_CLR(VR_MIICMD_CLK);
			DELAY(1);
			SIO_SET(VR_MIICMD_CLK);
			DELAY(1);
		}
		goto fail;
	}

	for (i = 0x8000; i; i >>= 1) {
		SIO_CLR(VR_MIICMD_CLK);
		DELAY(1);
		if (!ack) {
			if (CSR_READ_4(sc, VR_MIICMD) & VR_MIICMD_DATAIN)
				frame->mii_data |= i;
			DELAY(1);
		}
		SIO_SET(VR_MIICMD_CLK);
		DELAY(1);
	}

fail:

	SIO_CLR(VR_MIICMD_CLK);
	DELAY(1);
	SIO_SET(VR_MIICMD_CLK);
	DELAY(1);

	splx(s);

	if (ack)
		return (1);
	return (0);
}

/*
 * Write to a PHY register through the MII.
 */
static int vr_mii_writereg(sc, frame)
	struct vr_softc		*sc;
	struct vr_mii_frame	*frame;
{
	int			s;

	s = splimp();

	CSR_WRITE_1(sc, VR_MIICMD, 0);
	VR_SETBIT(sc, VR_MIICMD, VR_MIICMD_DIRECTPGM);

	/*
	 * Set up frame for TX.
	 */

	frame->mii_stdelim = VR_MII_STARTDELIM;
	frame->mii_opcode = VR_MII_WRITEOP;
	frame->mii_turnaround = VR_MII_TURNAROUND;

	/*
	 * Turn on data output.
	 */
	SIO_SET(VR_MIICMD_DIR);

	vr_mii_sync(sc);

	vr_mii_send(sc, frame->mii_stdelim, 2);
	vr_mii_send(sc, frame->mii_opcode, 2);
	vr_mii_send(sc, frame->mii_phyaddr, 5);
	vr_mii_send(sc, frame->mii_regaddr, 5);
	vr_mii_send(sc, frame->mii_turnaround, 2);
	vr_mii_send(sc, frame->mii_data, 16);

	/* Idle bit. */
	SIO_SET(VR_MIICMD_CLK);
	DELAY(1);
	SIO_CLR(VR_MIICMD_CLK);
	DELAY(1);

	/*
	 * Turn off xmit.
	 */
	SIO_CLR(VR_MIICMD_DIR);

	splx(s);

	return (0);
}

static u_int16_t vr_phy_readreg(sc, reg)
	struct vr_softc		*sc;
	int			reg;
{
	struct vr_mii_frame	frame;

	bzero((char *)&frame, sizeof (frame));

	frame.mii_phyaddr = sc->vr_phy_addr;
	frame.mii_regaddr = reg;
	vr_mii_readreg(sc, &frame);

	return (frame.mii_data);
}

static void vr_phy_writereg(sc, reg, data)
	struct vr_softc		*sc;
	u_int16_t		reg;
	u_int16_t		data;
{
	struct vr_mii_frame	frame;

	bzero((char *)&frame, sizeof (frame));

	frame.mii_phyaddr = sc->vr_phy_addr;
	frame.mii_regaddr = reg;
	frame.mii_data = data;

	vr_mii_writereg(sc, &frame);

	return;
}

/*
 * Calculate CRC of a multicast group address, return the lower 6 bits.
 */
static u_int8_t vr_calchash(addr)
	u_int8_t		*addr;
{
	u_int32_t		crc, carry;
	int			i, j;
	u_int8_t		c;

	/* Compute CRC for the address value. */
	crc = 0xFFFFFFFF; /* initial value */

	for (i = 0; i < 6; i++) {
		c = *(addr + i);
		for (j = 0; j < 8; j++) {
			carry = ((crc & 0x80000000) ? 1 : 0) ^ (c & 0x01);
			crc <<= 1;
			c >>= 1;
			if (carry)
				crc = (crc ^ 0x04c11db6) | carry;
		}
	}

	/* return the filter bit position */
	return ((crc >> 26) & 0x0000003F);
}

/*
 * Program the 64-bit multicast hash filter.
 */
static void vr_setmulti(sc)
	struct vr_softc		*sc;
{
	struct ifnet		*ifp;
	int			h = 0;
	u_int32_t		hashes[2] = { 0, 0 };
	struct ether_multistep	step;
	struct ether_multi	*enm;
	int			mcnt = 0;
	u_int8_t		rxfilt;

	ifp = &sc->vr_ec.ec_if;

	rxfilt = CSR_READ_1(sc, VR_RXCFG);

	if (ifp->if_flags & IFF_ALLMULTI || ifp->if_flags & IFF_PROMISC) {
		rxfilt |= VR_RXCFG_RX_MULTI;
		CSR_WRITE_1(sc, VR_RXCFG, rxfilt);
		CSR_WRITE_4(sc, VR_MAR0, 0xFFFFFFFF);
		CSR_WRITE_4(sc, VR_MAR1, 0xFFFFFFFF);
		return;
	}

	/* first, zot all the existing hash bits */
	CSR_WRITE_4(sc, VR_MAR0, 0);
	CSR_WRITE_4(sc, VR_MAR1, 0);

	/* now program new ones */
	ETHER_FIRST_MULTI(step, &sc->vr_ec, enm);
	while (enm != NULL) {
		if (memcmp(enm->enm_addrlo, enm->enm_addrhi, 6) != 0)
			continue;

		h = vr_calchash(enm->enm_addrlo);

		if (h < 32)
			hashes[0] |= (1 << h);
		else
			hashes[1] |= (1 << (h - 32));
		ETHER_NEXT_MULTI(step, enm);
		mcnt++;
	}

	if (mcnt)
		rxfilt |= VR_RXCFG_RX_MULTI;
	else
		rxfilt &= ~VR_RXCFG_RX_MULTI;

	CSR_WRITE_4(sc, VR_MAR0, hashes[0]);
	CSR_WRITE_4(sc, VR_MAR1, hashes[1]);
	CSR_WRITE_1(sc, VR_RXCFG, rxfilt);

	return;
}

/*
 * Initiate an autonegotiation session.
 */
static void vr_autoneg_xmit(sc)
	struct vr_softc		*sc;
{
	u_int16_t		phy_sts;

	vr_phy_writereg(sc, PHY_BMCR, PHY_BMCR_RESET);
	DELAY(500);
	while (vr_phy_readreg(sc, PHY_BMCR)
			& PHY_BMCR_RESET);

	phy_sts = vr_phy_readreg(sc, PHY_BMCR);
	phy_sts |= PHY_BMCR_AUTONEGENBL|PHY_BMCR_AUTONEGRSTR;
	vr_phy_writereg(sc, PHY_BMCR, phy_sts);

	return;
}

/*
 * Invoke autonegotiation on a PHY.
 */
static void vr_autoneg_mii(sc, flag, verbose)
	struct vr_softc		*sc;
	int			flag;
	int			verbose;
{
	u_int16_t		phy_sts = 0, media, advert, ability;
	struct ifnet		*ifp;
	struct ifmedia		*ifm;

	ifm = &sc->ifmedia;
	ifp = &sc->vr_ec.ec_if;

	ifm->ifm_media = IFM_ETHER | IFM_AUTO;

	/*
	 * The 100baseT4 PHY on the 3c905-T4 has the 'autoneg supported'
	 * bit cleared in the status register, but has the 'autoneg enabled'
	 * bit set in the control register. This is a contradiction, and
	 * I'm not sure how to handle it. If you want to force an attempt
	 * to autoneg for 100baseT4 PHYs, #define FORCE_AUTONEG_TFOUR
	 * and see what happens.
	 */
#ifndef FORCE_AUTONEG_TFOUR
	/*
	 * First, see if autoneg is supported. If not, there's
	 * no point in continuing.
	 */
	phy_sts = vr_phy_readreg(sc, PHY_BMSR);
	if (!(phy_sts & PHY_BMSR_CANAUTONEG)) {
		if (verbose)
			printf("%s: autonegotiation not supported\n",
				sc->vr_dev.dv_xname);
		ifm->ifm_media = IFM_ETHER|IFM_10_T|IFM_HDX;
		return;
	}
#endif

	switch (flag) {
	case VR_FLAG_FORCEDELAY:
		/*
		 * XXX Never use this option anywhere but in the probe
		 * routine: making the kernel stop dead in its tracks
		 * for three whole seconds after we've gone multi-user
		 * is really bad manners.
		 */
		vr_autoneg_xmit(sc);
		DELAY(5000000);
		break;
	case VR_FLAG_SCHEDDELAY:
		/*
		 * Wait for the transmitter to go idle before starting
		 * an autoneg session, otherwise vr_start() may clobber
		 * our timeout, and we don't want to allow transmission
		 * during an autoneg session since that can screw it up.
		 */
		if (sc->vr_cdata.vr_tx_head != NULL) {
			sc->vr_want_auto = 1;
			return;
		}
		vr_autoneg_xmit(sc);
		ifp->if_timer = 5;
		sc->vr_autoneg = 1;
		sc->vr_want_auto = 0;
		return;
		break;
	case VR_FLAG_DELAYTIMEO:
		ifp->if_timer = 0;
		sc->vr_autoneg = 0;
		break;
	default:
		printf("%s: invalid autoneg flag: %d\n",
			sc->vr_dev.dv_xname, flag);
		return;
	}

	if (vr_phy_readreg(sc, PHY_BMSR) & PHY_BMSR_AUTONEGCOMP) {
		if (verbose)
			printf("%s: autoneg complete, ",
				sc->vr_dev.dv_xname);
		phy_sts = vr_phy_readreg(sc, PHY_BMSR);
	} else {
		if (verbose)
			printf("%s: autoneg not complete, ",
				sc->vr_dev.dv_xname);
	}

	media = vr_phy_readreg(sc, PHY_BMCR);

	/* Link is good. Report modes and set duplex mode. */
	if (vr_phy_readreg(sc, PHY_BMSR) & PHY_BMSR_LINKSTAT) {
		if (verbose)
			printf("link status good ");
		advert = vr_phy_readreg(sc, PHY_ANAR);
		ability = vr_phy_readreg(sc, PHY_LPAR);

		if (advert & PHY_ANAR_100BT4 && ability & PHY_ANAR_100BT4) {
			ifm->ifm_media = IFM_ETHER|IFM_100_T4;
			media |= PHY_BMCR_SPEEDSEL;
			media &= ~PHY_BMCR_DUPLEX;
			printf("(100baseT4)\n");
		} else if (advert & PHY_ANAR_100BTXFULL &&
			ability & PHY_ANAR_100BTXFULL) {
			ifm->ifm_media = IFM_ETHER|IFM_100_TX|IFM_FDX;
			media |= PHY_BMCR_SPEEDSEL;
			media |= PHY_BMCR_DUPLEX;
			printf("(full-duplex, 100Mbps)\n");
		} else if (advert & PHY_ANAR_100BTXHALF &&
			ability & PHY_ANAR_100BTXHALF) {
			ifm->ifm_media = IFM_ETHER|IFM_100_TX|IFM_HDX;
			media |= PHY_BMCR_SPEEDSEL;
			media &= ~PHY_BMCR_DUPLEX;
			printf("(half-duplex, 100Mbps)\n");
		} else if (advert & PHY_ANAR_10BTFULL &&
			ability & PHY_ANAR_10BTFULL) {
			ifm->ifm_media = IFM_ETHER|IFM_10_T|IFM_FDX;
			media &= ~PHY_BMCR_SPEEDSEL;
			media |= PHY_BMCR_DUPLEX;
			printf("(full-duplex, 10Mbps)\n");
		} else {
			ifm->ifm_media = IFM_ETHER|IFM_10_T|IFM_HDX;
			media &= ~PHY_BMCR_SPEEDSEL;
			media &= ~PHY_BMCR_DUPLEX;
			printf("(half-duplex, 10Mbps)\n");
		}

		media &= ~PHY_BMCR_AUTONEGENBL;

		/* Set ASIC's duplex mode to match the PHY. */
		vr_setcfg(sc, media);
		vr_phy_writereg(sc, PHY_BMCR, media);
	} else {
		if (verbose)
			printf("no carrier\n");
	}

	vr_init(sc);

	if (sc->vr_tx_pend) {
		sc->vr_autoneg = 0;
		sc->vr_tx_pend = 0;
		vr_start(ifp);
	}

	return;
}

static void vr_getmode_mii(sc)
	struct vr_softc		*sc;
{
	u_int16_t		bmsr;
	struct ifnet		*ifp;

	ifp = &sc->vr_ec.ec_if;

	bmsr = vr_phy_readreg(sc, PHY_BMSR);

	/* fallback */
	sc->ifmedia.ifm_media = IFM_ETHER|IFM_10_T|IFM_HDX;

	if (bmsr & PHY_BMSR_10BTHALF) {
		ifmedia_add(&sc->ifmedia,
			IFM_ETHER|IFM_10_T|IFM_HDX, 0, NULL);
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_10_T, 0, NULL);
	}

	if (bmsr & PHY_BMSR_10BTFULL) {
		ifmedia_add(&sc->ifmedia,
			IFM_ETHER|IFM_10_T|IFM_FDX, 0, NULL);
		sc->ifmedia.ifm_media = IFM_ETHER|IFM_10_T|IFM_FDX;
	}

	if (bmsr & PHY_BMSR_100BTXHALF) {
		ifp->if_baudrate = 100000000;
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_100_TX, 0, NULL);
		ifmedia_add(&sc->ifmedia,
			IFM_ETHER|IFM_100_TX|IFM_HDX, 0, NULL);
		sc->ifmedia.ifm_media = IFM_ETHER|IFM_100_TX|IFM_HDX;
	}

	if (bmsr & PHY_BMSR_100BTXFULL) {
		ifp->if_baudrate = 100000000;
		ifmedia_add(&sc->ifmedia,
			IFM_ETHER|IFM_100_TX|IFM_FDX, 0, NULL);
		sc->ifmedia.ifm_media = IFM_ETHER|IFM_100_TX|IFM_FDX;
	}

	/* Some also support 100BaseT4. */
	if (bmsr & PHY_BMSR_100BT4) {
		ifp->if_baudrate = 100000000;
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_100_T4, 0, NULL);
		sc->ifmedia.ifm_media = IFM_ETHER|IFM_100_T4;
#ifdef FORCE_AUTONEG_TFOUR
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_AUTO, 0 NULL):
		sc->ifmedia.ifm_media = IFM_ETHER|IFM_AUTO;
#endif
	}

	if (bmsr & PHY_BMSR_CANAUTONEG) {
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_AUTO, 0, NULL);
		sc->ifmedia.ifm_media = IFM_ETHER|IFM_AUTO;
	}

	return;
}

/*
 * Set speed and duplex mode.
 */
static void vr_setmode_mii(sc, media)
	struct vr_softc		*sc;
	int			media;
{
	u_int16_t		bmcr;
	struct ifnet		*ifp;

	ifp = &sc->vr_ec.ec_if;

	/*
	 * If an autoneg session is in progress, stop it.
	 */
	if (sc->vr_autoneg) {
		printf("%s: canceling autoneg session\n",
			sc->vr_dev.dv_xname);
		ifp->if_timer = sc->vr_autoneg = sc->vr_want_auto = 0;
		bmcr = vr_phy_readreg(sc, PHY_BMCR);
		bmcr &= ~PHY_BMCR_AUTONEGENBL;
		vr_phy_writereg(sc, PHY_BMCR, bmcr);
	}

	printf("%s: selecting MII, ", sc->vr_dev.dv_xname);

	bmcr = vr_phy_readreg(sc, PHY_BMCR);

	bmcr &= ~(PHY_BMCR_AUTONEGENBL|PHY_BMCR_SPEEDSEL|
			PHY_BMCR_DUPLEX|PHY_BMCR_LOOPBK);

	if (IFM_SUBTYPE(media) == IFM_100_T4) {
		printf("100Mbps/T4, half-duplex\n");
		bmcr |= PHY_BMCR_SPEEDSEL;
		bmcr &= ~PHY_BMCR_DUPLEX;
	}

	if (IFM_SUBTYPE(media) == IFM_100_TX) {
		printf("100Mbps, ");
		bmcr |= PHY_BMCR_SPEEDSEL;
	}

	if (IFM_SUBTYPE(media) == IFM_10_T) {
		printf("10Mbps, ");
		bmcr &= ~PHY_BMCR_SPEEDSEL;
	}

	if ((media & IFM_GMASK) == IFM_FDX) {
		printf("full duplex\n");
		bmcr |= PHY_BMCR_DUPLEX;
	} else {
		printf("half duplex\n");
		bmcr &= ~PHY_BMCR_DUPLEX;
	}

	vr_setcfg(sc, bmcr);
	vr_phy_writereg(sc, PHY_BMCR, bmcr);

	return;
}

/*
 * In order to fiddle with the
 * 'full-duplex' and '100Mbps' bits in the netconfig register, we
 * first have to put the transmit and/or receive logic in the idle state.
 */
static void vr_setcfg(sc, bmcr)
	struct vr_softc		*sc;
	u_int16_t		bmcr;
{
	int			restart = 0;

	if (CSR_READ_2(sc, VR_COMMAND) & (VR_CMD_TX_ON|VR_CMD_RX_ON)) {
		restart = 1;
		VR_CLRBIT16(sc, VR_COMMAND, (VR_CMD_TX_ON|VR_CMD_RX_ON));
	}

	if (bmcr & PHY_BMCR_DUPLEX)
		VR_SETBIT16(sc, VR_COMMAND, VR_CMD_FULLDUPLEX);
	else
		VR_CLRBIT16(sc, VR_COMMAND, VR_CMD_FULLDUPLEX);

	if (restart)
		VR_SETBIT16(sc, VR_COMMAND, VR_CMD_TX_ON|VR_CMD_RX_ON);

	return;
}

static void vr_reset(sc)
	struct vr_softc		*sc;
{
	register int		i;

	VR_SETBIT16(sc, VR_COMMAND, VR_CMD_RESET);

	for (i = 0; i < VR_TIMEOUT; i++) {
		DELAY(10);
		if (!(CSR_READ_2(sc, VR_COMMAND) & VR_CMD_RESET))
			break;
	}
	if (i == VR_TIMEOUT)
		printf("%s: reset never completed!\n",
			sc->vr_dev.dv_xname);

	/* Wait a little while for the chip to get its brains in order. */
	DELAY(1000);

	return;
}

/*
 * Initialize the transmit descriptors.
 */
static int vr_list_tx_init(sc)
	struct vr_softc		*sc;
{
	struct vr_chain_data	*cd;
	struct vr_list_data	*ld;
	int			i;

	cd = &sc->vr_cdata;
	ld = sc->vr_ldata;
	for (i = 0; i < VR_TX_LIST_CNT; i++) {
		cd->vr_tx_chain[i].vr_ptr = &ld->vr_tx_list[i];
		if (i == (VR_TX_LIST_CNT - 1))
			cd->vr_tx_chain[i].vr_nextdesc =
				&cd->vr_tx_chain[0];
		else
			cd->vr_tx_chain[i].vr_nextdesc =
				&cd->vr_tx_chain[i + 1];
	}

	cd->vr_tx_free = &cd->vr_tx_chain[0];
	cd->vr_tx_tail = cd->vr_tx_head = NULL;

	return (0);
}


/*
 * Initialize the RX descriptors and allocate mbufs for them. Note that
 * we arrange the descriptors in a closed ring, so that the last descriptor
 * points back to the first.
 */
static int vr_list_rx_init(sc)
	struct vr_softc		*sc;
{
	struct vr_chain_data	*cd;
	struct vr_list_data	*ld;
	int			i;

	cd = &sc->vr_cdata;
	ld = sc->vr_ldata;

	for (i = 0; i < VR_RX_LIST_CNT; i++) {
		cd->vr_rx_chain[i].vr_ptr =
			(struct vr_desc *)&ld->vr_rx_list[i];
		if (vr_newbuf(sc, &cd->vr_rx_chain[i]) == ENOBUFS)
			return (ENOBUFS);
		if (i == (VR_RX_LIST_CNT - 1)) {
			cd->vr_rx_chain[i].vr_nextdesc =
					&cd->vr_rx_chain[0];
			ld->vr_rx_list[i].vr_next =
					vtophys(&ld->vr_rx_list[0]);
		} else {
			cd->vr_rx_chain[i].vr_nextdesc =
					&cd->vr_rx_chain[i + 1];
			ld->vr_rx_list[i].vr_next =
					vtophys(&ld->vr_rx_list[i + 1]);
		}
	}

	cd->vr_rx_head = &cd->vr_rx_chain[0];

	return (0);
}

/*
 * Initialize an RX descriptor and attach an MBUF cluster.
 * Note: the length fields are only 11 bits wide, which means the
 * largest size we can specify is 2047. This is important because
 * MCLBYTES is 2048, so we have to subtract one otherwise we'll
 * overflow the field and make a mess.
 */
static int vr_newbuf(sc, c)
	struct vr_softc		*sc;
	struct vr_chain_onefrag	*c;
{
	struct mbuf		*m_new = NULL;

	MGETHDR(m_new, M_DONTWAIT, MT_DATA);
	if (m_new == NULL) {
		printf("%s: no memory for rx list -- packet dropped!\n",
			sc->vr_dev.dv_xname);
		return (ENOBUFS);
	}

	MCLGET(m_new, M_DONTWAIT);
	if (!(m_new->m_flags & M_EXT)) {
		printf("%s: no memory for rx list -- packet dropped!\n",
			sc->vr_dev.dv_xname);
		m_freem(m_new);
		return (ENOBUFS);
	}

	c->vr_mbuf = m_new;
	c->vr_ptr->vr_status = VR_RXSTAT;
	c->vr_ptr->vr_data = vtophys(mtod(m_new, caddr_t));
	c->vr_ptr->vr_ctl = VR_RXCTL | VR_RXLEN;

	return (0);
}

/*
 * A frame has been uploaded: pass the resulting mbuf chain up to
 * the higher level protocols.
 */
static void vr_rxeof(sc)
	struct vr_softc		*sc;
{
	struct ether_header	*eh;
	struct mbuf		*m;
	struct ifnet		*ifp;
	struct vr_chain_onefrag	*cur_rx;
	int			total_len = 0;
	u_int32_t		rxstat;

	ifp = &sc->vr_ec.ec_if;

	while (!((rxstat = sc->vr_cdata.vr_rx_head->vr_ptr->vr_status) &
							VR_RXSTAT_OWN)) {
		cur_rx = sc->vr_cdata.vr_rx_head;
		sc->vr_cdata.vr_rx_head = cur_rx->vr_nextdesc;

		/*
		 * If an error occurs, update stats, clear the
		 * status word and leave the mbuf cluster in place:
		 * it should simply get re-used next time this descriptor
		 * comes up in the ring.
		 */
		if (rxstat & VR_RXSTAT_RXERR) {
			ifp->if_ierrors++;
			printf("%s: rx error: ", sc->vr_dev.dv_xname);
			switch (rxstat & 0x000000FF) {
			case VR_RXSTAT_CRCERR:
				printf("crc error\n");
				break;
			case VR_RXSTAT_FRAMEALIGNERR:
				printf("frame alignment error\n");
				break;
			case VR_RXSTAT_FIFOOFLOW:
				printf("FIFO overflow\n");
				break;
			case VR_RXSTAT_GIANT:
				printf("received giant packet\n");
				break;
			case VR_RXSTAT_RUNT:
				printf("received runt packet\n");
				break;
			case VR_RXSTAT_BUSERR:
				printf("system bus error\n");
				break;
			case VR_RXSTAT_BUFFERR:
				printf("rx buffer error\n");
				break;
			default:
				printf("unknown rx error\n");
				break;
			}
			cur_rx->vr_ptr->vr_status = VR_RXSTAT;
			cur_rx->vr_ptr->vr_ctl = VR_RXCTL|VR_RXLEN;
			continue;
		}

		/* No errors; receive the packet. */
		m = cur_rx->vr_mbuf;
		total_len = VR_RXBYTES(cur_rx->vr_ptr->vr_status);

		/*
		 * XXX The VIA Rhine chip includes the CRC with every
		 * received frame, and there's no way to turn this
		 * behavior off (at least, I can't find anything in
		 * the manual that explains how to do it) so we have
		 * to trim off the CRC manually.
		 */
		total_len -= ETHER_CRC_LEN;

		/*
		 * Try to conjure up a new mbuf cluster. If that
		 * fails, it means we have an out of memory condition and
		 * should leave the buffer in place and continue. This will
		 * result in a lost packet, but there's little else we
		 * can do in this situation.
		 */
		if (vr_newbuf(sc, cur_rx) == ENOBUFS) {
			ifp->if_ierrors++;
			cur_rx->vr_ptr->vr_status = VR_RXSTAT;
			cur_rx->vr_ptr->vr_ctl = VR_RXCTL|VR_RXLEN;
			continue;
		}

		ifp->if_ipackets++;
		eh = mtod(m, struct ether_header *);
		m->m_pkthdr.rcvif = ifp;
		m->m_pkthdr.len = m->m_len = total_len;
#if NBPFILTER > 0
		/*
		 * Handle BPF listeners. Let the BPF user see the packet, but
		 * don't pass it up to the ether_input() layer unless it's
		 * a broadcast packet, multicast packet, matches our ethernet
		 * address or the interface is in promiscuous mode.
		 */
		if (ifp->if_bpf) {
			bpf_mtap(ifp->if_bpf, m);
			if (ifp->if_flags & IFF_PROMISC &&
				(memcmp(eh->ether_dhost, sc->vr_enaddr,
						ETHER_ADDR_LEN) &&
					(eh->ether_dhost[0] & 1) == 0)) {
				m_freem(m);
				continue;
			}
		}
#endif
		/* Remove header from mbuf and pass it on. */
		m_adj(m, sizeof (struct ether_header));
		ether_input(ifp, eh, m);
	}

	return;
}

void vr_rxeoc(sc)
	struct vr_softc		*sc;
{

	vr_rxeof(sc);
	VR_CLRBIT16(sc, VR_COMMAND, VR_CMD_RX_ON);
	CSR_WRITE_4(sc, VR_RXADDR, vtophys(sc->vr_cdata.vr_rx_head->vr_ptr));
	VR_SETBIT16(sc, VR_COMMAND, VR_CMD_RX_ON);
	VR_SETBIT16(sc, VR_COMMAND, VR_CMD_RX_GO);

	return;
}

/*
 * A frame was downloaded to the chip. It's safe for us to clean up
 * the list buffers.
 */

static void vr_txeof(sc)
	struct vr_softc		*sc;
{
	struct vr_chain		*cur_tx;
	struct ifnet		*ifp;
	register struct mbuf	*n;

	ifp = &sc->vr_ec.ec_if;

	/* Clear the timeout timer. */
	ifp->if_timer = 0;

	/* Sanity check. */
	if (sc->vr_cdata.vr_tx_head == NULL)
		return;

	/*
	 * Go through our tx list and free mbufs for those
	 * frames that have been transmitted.
	 */
	while (sc->vr_cdata.vr_tx_head->vr_mbuf != NULL) {
		u_int32_t		txstat;

		cur_tx = sc->vr_cdata.vr_tx_head;
		txstat = cur_tx->vr_ptr->vr_status;

		if (txstat & VR_TXSTAT_OWN)
			break;

		if (txstat & VR_TXSTAT_ERRSUM) {
			ifp->if_oerrors++;
			if (txstat & VR_TXSTAT_DEFER)
				ifp->if_collisions++;
			if (txstat & VR_TXSTAT_LATECOLL)
				ifp->if_collisions++;
		}

		ifp->if_collisions +=(txstat & VR_TXSTAT_COLLCNT) >> 3;

		ifp->if_opackets++;
		MFREE(cur_tx->vr_mbuf, n);
		cur_tx->vr_mbuf = NULL;

		if (sc->vr_cdata.vr_tx_head == sc->vr_cdata.vr_tx_tail) {
			sc->vr_cdata.vr_tx_head = NULL;
			sc->vr_cdata.vr_tx_tail = NULL;
			break;
		}

		sc->vr_cdata.vr_tx_head = cur_tx->vr_nextdesc;
	}

	return;
}

/*
 * TX 'end of channel' interrupt handler.
 */
static void vr_txeoc(sc)
	struct vr_softc		*sc;
{
	struct ifnet		*ifp;

	ifp = &sc->vr_ec.ec_if;

	ifp->if_timer = 0;

	if (sc->vr_cdata.vr_tx_head == NULL) {
		ifp->if_flags &= ~IFF_OACTIVE;
		sc->vr_cdata.vr_tx_tail = NULL;
		if (sc->vr_want_auto)
			vr_autoneg_mii(sc, VR_FLAG_SCHEDDELAY, 1);
	}

	return;
}

static void vr_intr(arg)
	void			*arg;
{
	struct vr_softc		*sc;
	struct ifnet		*ifp;
	u_int16_t		status;

	sc = arg;
	ifp = &sc->vr_ec.ec_if;

	/* Supress unwanted interrupts. */
	if (!(ifp->if_flags & IFF_UP)) {
		vr_stop(sc);
		return;
	}

	/* Disable interrupts. */
	CSR_WRITE_2(sc, VR_IMR, 0x0000);

	for (;;) {

		status = CSR_READ_2(sc, VR_ISR);
		if (status)
			CSR_WRITE_2(sc, VR_ISR, status);

		if ((status & VR_INTRS) == 0)
			break;

		if (status & VR_ISR_RX_OK)
			vr_rxeof(sc);

		if ((status & VR_ISR_RX_ERR) || (status & VR_ISR_RX_NOBUF) ||
		    (status & VR_ISR_RX_NOBUF) || (status & VR_ISR_RX_OFLOW) ||
		    (status & VR_ISR_RX_DROPPED)) {
			vr_rxeof(sc);
			vr_rxeoc(sc);
		}

		if (status & VR_ISR_TX_OK) {
			vr_txeof(sc);
			vr_txeoc(sc);
		}

		if ((status & VR_ISR_TX_UNDERRUN)||(status & VR_ISR_TX_ABRT)) {
			ifp->if_oerrors++;
			vr_txeof(sc);
			if (sc->vr_cdata.vr_tx_head != NULL) {
				VR_SETBIT16(sc, VR_COMMAND, VR_CMD_TX_ON);
				VR_SETBIT16(sc, VR_COMMAND, VR_CMD_TX_GO);
			}
		}

		if (status & VR_ISR_BUSERR) {
			vr_reset(sc);
			vr_init(sc);
		}
	}

	/* Re-enable interrupts. */
	CSR_WRITE_2(sc, VR_IMR, VR_INTRS);

	if (ifp->if_snd.ifq_head != NULL) {
		vr_start(ifp);
	}

	return;
}

/*
 * Encapsulate an mbuf chain in a descriptor by coupling the mbuf data
 * pointers to the fragment pointers.
 */
static int vr_encap(sc, c, m_head)
	struct vr_softc		*sc;
	struct vr_chain		*c;
	struct mbuf		*m_head;
{
	int			frag = 0;
	struct vr_desc		*f = NULL;
	int			total_len;
	struct mbuf		*m;

	m = m_head;
	total_len = 0;

	/*
	 * The VIA Rhine wants packet buffers to be longword
	 * aligned, but very often our mbufs aren't. Rather than
	 * waste time trying to decide when to copy and when not
	 * to copy, just do it all the time.
	 */
	if (m != NULL) {
		struct mbuf		*m_new = NULL;

		MGETHDR(m_new, M_DONTWAIT, MT_DATA);
		if (m_new == NULL) {
			printf("%s: no memory for tx list",
				sc->vr_dev.dv_xname);
			return (1);
		}
		if (m_head->m_pkthdr.len > MHLEN) {
			MCLGET(m_new, M_DONTWAIT);
			if (!(m_new->m_flags & M_EXT)) {
				m_freem(m_new);
				printf("%s: no memory for tx list",
					sc->vr_dev.dv_xname);
				return (1);
			}
		}
		m_copydata(m_head, 0, m_head->m_pkthdr.len,
					mtod(m_new, caddr_t));
		m_new->m_pkthdr.len = m_new->m_len = m_head->m_pkthdr.len;
		m_freem(m_head);
		m_head = m_new;
		/*
		 * The Rhine chip doesn't auto-pad, so we have to make
		 * sure to pad short frames out to the minimum frame length
		 * ourselves.
		 */
		if (m_head->m_len < VR_MIN_FRAMELEN) {
			m_new->m_pkthdr.len += VR_MIN_FRAMELEN - m_new->m_len;
			m_new->m_len = m_new->m_pkthdr.len;
		}
		f = c->vr_ptr;
		f->vr_data = vtophys(mtod(m_new, caddr_t));
		f->vr_ctl = total_len = m_new->m_len;
		f->vr_ctl |= VR_TXCTL_TLINK|VR_TXCTL_FIRSTFRAG;
		f->vr_status = 0;
		frag = 1;
	}

	c->vr_mbuf = m_head;
	c->vr_ptr->vr_ctl |= VR_TXCTL_LASTFRAG|VR_TXCTL_FINT;
	c->vr_ptr->vr_next = vtophys(c->vr_nextdesc->vr_ptr);

	return (0);
}

/*
 * Main transmit routine. To avoid having to do mbuf copies, we put pointers
 * to the mbuf data regions directly in the transmit lists. We also save a
 * copy of the pointers since the transmit list fragment pointers are
 * physical addresses.
 */

static void vr_start(ifp)
	struct ifnet		*ifp;
{
	struct vr_softc		*sc;
	struct mbuf		*m_head = NULL;
	struct vr_chain		*cur_tx = NULL, *start_tx;

	sc = ifp->if_softc;

	if (sc->vr_autoneg) {
		sc->vr_tx_pend = 1;
		return;
	}

	/*
	 * Check for an available queue slot. If there are none,
	 * punt.
	 */
	if (sc->vr_cdata.vr_tx_free->vr_mbuf != NULL) {
		ifp->if_flags |= IFF_OACTIVE;
		return;
	}

	start_tx = sc->vr_cdata.vr_tx_free;

	while (sc->vr_cdata.vr_tx_free->vr_mbuf == NULL) {
		IF_DEQUEUE(&ifp->if_snd, m_head);
		if (m_head == NULL)
			break;

		/* Pick a descriptor off the free list. */
		cur_tx = sc->vr_cdata.vr_tx_free;
		sc->vr_cdata.vr_tx_free = cur_tx->vr_nextdesc;

		/* Pack the data into the descriptor. */
		vr_encap(sc, cur_tx, m_head);

		if (cur_tx != start_tx)
			VR_TXOWN(cur_tx) = VR_TXSTAT_OWN;

#if NBPFILTER > 0
		/*
		 * If there's a BPF listener, bounce a copy of this frame
		 * to him.
		 */
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, cur_tx->vr_mbuf);
#endif
		VR_TXOWN(cur_tx) = VR_TXSTAT_OWN;
		VR_SETBIT16(sc, VR_COMMAND, VR_CMD_TX_ON|VR_CMD_TX_GO);
	}

	/*
	 * If there are no frames queued, bail.
	 */
	if (cur_tx == NULL)
		return;

	sc->vr_cdata.vr_tx_tail = cur_tx;

	if (sc->vr_cdata.vr_tx_head == NULL)
		sc->vr_cdata.vr_tx_head = start_tx;

	/*
	 * Set a timeout in case the chip goes out to lunch.
	 */
	ifp->if_timer = 5;

	return;
}

static void vr_init(xsc)
	void			*xsc;
{
	struct vr_softc		*sc = xsc;
	struct ifnet		*ifp = &sc->vr_ec.ec_if;
	u_int16_t		phy_bmcr = 0;
	int			s;

	if (sc->vr_autoneg)
		return;

	s = splimp();

	if (sc->vr_pinfo != NULL)
		phy_bmcr = vr_phy_readreg(sc, PHY_BMCR);

	/*
	 * Cancel pending I/O and free all RX/TX buffers.
	 */
	vr_stop(sc);
	vr_reset(sc);

	VR_CLRBIT(sc, VR_RXCFG, VR_RXCFG_RX_THRESH);
	VR_SETBIT(sc, VR_RXCFG, VR_RXTHRESH_STORENFWD);

	VR_CLRBIT(sc, VR_TXCFG, VR_TXCFG_TX_THRESH);
	VR_SETBIT(sc, VR_TXCFG, VR_TXTHRESH_STORENFWD);

	/* Init circular RX list. */
	if (vr_list_rx_init(sc) == ENOBUFS) {
		printf("%s: initialization failed: no "
			"memory for rx buffers\n", sc->vr_dev.dv_xname);
		vr_stop(sc);
		(void)splx(s);
		return;
	}

	/*
	 * Init tx descriptors.
	 */
	vr_list_tx_init(sc);

	/* If we want promiscuous mode, set the allframes bit. */
	if (ifp->if_flags & IFF_PROMISC)
		VR_SETBIT(sc, VR_RXCFG, VR_RXCFG_RX_PROMISC);
	else
		VR_CLRBIT(sc, VR_RXCFG, VR_RXCFG_RX_PROMISC);

	/* Set capture broadcast bit to capture broadcast frames. */
	if (ifp->if_flags & IFF_BROADCAST)
		VR_SETBIT(sc, VR_RXCFG, VR_RXCFG_RX_BROAD);
	else
		VR_CLRBIT(sc, VR_RXCFG, VR_RXCFG_RX_BROAD);

	/*
	 * Program the multicast filter, if necessary.
	 */
	vr_setmulti(sc);

	/*
	 * Load the address of the RX list.
	 */
	CSR_WRITE_4(sc, VR_RXADDR, vtophys(sc->vr_cdata.vr_rx_head->vr_ptr));

	/* Enable receiver and transmitter. */
	CSR_WRITE_2(sc, VR_COMMAND, VR_CMD_TX_NOPOLL|VR_CMD_START|
				    VR_CMD_TX_ON|VR_CMD_RX_ON|
				    VR_CMD_RX_GO);

	vr_setcfg(sc, vr_phy_readreg(sc, PHY_BMCR));

	CSR_WRITE_4(sc, VR_TXADDR, vtophys(&sc->vr_ldata->vr_tx_list[0]));

	/*
	 * Enable interrupts.
	 */
	CSR_WRITE_2(sc, VR_ISR, 0xFFFF);
	CSR_WRITE_2(sc, VR_IMR, VR_INTRS);

	/* Restore state of BMCR */
	if (sc->vr_pinfo != NULL)
		vr_phy_writereg(sc, PHY_BMCR, phy_bmcr);

	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	(void)splx(s);

	return;
}

/*
 * Set media options.
 */
static int vr_ifmedia_upd(ifp)
	struct ifnet		*ifp;
{
	struct vr_softc		*sc;
	struct ifmedia		*ifm;

	sc = ifp->if_softc;
	ifm = &sc->ifmedia;

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	if (IFM_SUBTYPE(ifm->ifm_media) == IFM_AUTO)
		vr_autoneg_mii(sc, VR_FLAG_SCHEDDELAY, 1);
	else
		vr_setmode_mii(sc, ifm->ifm_media);

	return (0);
}

/*
 * Report current media status.
 */
static void vr_ifmedia_sts(ifp, ifmr)
	struct ifnet		*ifp;
	struct ifmediareq	*ifmr;
{
	struct vr_softc		*sc;
	u_int16_t		advert = 0, ability = 0;

	sc = ifp->if_softc;

	ifmr->ifm_active = IFM_ETHER;

	if (!(vr_phy_readreg(sc, PHY_BMCR) & PHY_BMCR_AUTONEGENBL)) {
		if (vr_phy_readreg(sc, PHY_BMCR) & PHY_BMCR_SPEEDSEL)
			ifmr->ifm_active = IFM_ETHER|IFM_100_TX;
		else
			ifmr->ifm_active = IFM_ETHER|IFM_10_T;
		if (vr_phy_readreg(sc, PHY_BMCR) & PHY_BMCR_DUPLEX)
			ifmr->ifm_active |= IFM_FDX;
		else
			ifmr->ifm_active |= IFM_HDX;
		return;
	}

	ability = vr_phy_readreg(sc, PHY_LPAR);
	advert = vr_phy_readreg(sc, PHY_ANAR);
	if (advert & PHY_ANAR_100BT4 &&
		ability & PHY_ANAR_100BT4) {
		ifmr->ifm_active = IFM_ETHER|IFM_100_T4;
	} else if (advert & PHY_ANAR_100BTXFULL &&
		ability & PHY_ANAR_100BTXFULL) {
		ifmr->ifm_active = IFM_ETHER|IFM_100_TX|IFM_FDX;
	} else if (advert & PHY_ANAR_100BTXHALF &&
		ability & PHY_ANAR_100BTXHALF) {
		ifmr->ifm_active = IFM_ETHER|IFM_100_TX|IFM_HDX;
	} else if (advert & PHY_ANAR_10BTFULL &&
		ability & PHY_ANAR_10BTFULL) {
		ifmr->ifm_active = IFM_ETHER|IFM_10_T|IFM_FDX;
	} else if (advert & PHY_ANAR_10BTHALF &&
		ability & PHY_ANAR_10BTHALF) {
		ifmr->ifm_active = IFM_ETHER|IFM_10_T|IFM_HDX;
	}

	return;
}

static int vr_ioctl(ifp, command, data)
	struct ifnet		*ifp;
	u_long			command;
	caddr_t			data;
{
	struct vr_softc		*sc = ifp->if_softc;
	struct ifreq		*ifr = (struct ifreq *)data;
	struct ifaddr		*ifa = (struct ifaddr *)data;
	int			s, error = 0;

	s = splimp();

	switch (command) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			vr_init(sc);
			arp_ifinit(ifp, ifa);
			break;
#endif /* INET */
		default:
			vr_init(sc);
			break;
		}
		break;

	case SIOCGIFADDR:
		bcopy((caddr_t) sc->vr_enaddr,
			(caddr_t) ((struct sockaddr *)&ifr->ifr_data)->sa_data,
			ETHER_ADDR_LEN);
		break;

	case SIOCSIFMTU:
		if (ifr->ifr_mtu > ETHERMTU)
			error = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;

	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			vr_init(sc);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				vr_stop(sc);
		}
		error = 0;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (command == SIOCADDMULTI)
			error = ether_addmulti(ifr, &sc->vr_ec);
		else
			error = ether_delmulti(ifr, &sc->vr_ec);

		if (error == ENETRESET) {
			vr_setmulti(sc);
			error = 0;
		}
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->ifmedia, command);
		break;
	default:
		error = EINVAL;
		break;
	}

	(void)splx(s);

	return (error);
}

static void vr_watchdog(ifp)
	struct ifnet		*ifp;
{
	struct vr_softc		*sc;

	sc = ifp->if_softc;

	if (sc->vr_autoneg) {
		vr_autoneg_mii(sc, VR_FLAG_DELAYTIMEO, 1);
		return;
	}

	ifp->if_oerrors++;
	printf("%s: watchdog timeout\n", sc->vr_dev.dv_xname);

	if (!(vr_phy_readreg(sc, PHY_BMSR) & PHY_BMSR_LINKSTAT))
		printf("%s: no carrier - transceiver cable problem?\n",
			sc->vr_dev.dv_xname);

	vr_stop(sc);
	vr_reset(sc);
	vr_init(sc);

	if (ifp->if_snd.ifq_head != NULL)
		vr_start(ifp);

	return;
}

/*
 * Stop the adapter and free any mbufs allocated to the
 * RX and TX lists.
 */
static void vr_stop(sc)
	struct vr_softc		*sc;
{
	register int		i;
	struct ifnet		*ifp;

	ifp = &sc->vr_ec.ec_if;
	ifp->if_timer = 0;

	VR_SETBIT16(sc, VR_COMMAND, VR_CMD_STOP);
	VR_CLRBIT16(sc, VR_COMMAND, (VR_CMD_RX_ON|VR_CMD_TX_ON));
	CSR_WRITE_2(sc, VR_IMR, 0x0000);
	CSR_WRITE_4(sc, VR_TXADDR, 0x00000000);
	CSR_WRITE_4(sc, VR_RXADDR, 0x00000000);

	/*
	 * Free data in the RX lists.
	 */
	for (i = 0; i < VR_RX_LIST_CNT; i++) {
		if (sc->vr_cdata.vr_rx_chain[i].vr_mbuf != NULL) {
			m_freem(sc->vr_cdata.vr_rx_chain[i].vr_mbuf);
			sc->vr_cdata.vr_rx_chain[i].vr_mbuf = NULL;
		}
	}
	bzero((char *)&sc->vr_ldata->vr_rx_list,
		sizeof (sc->vr_ldata->vr_rx_list));

	/*
	 * Free the TX list buffers.
	 */
	for (i = 0; i < VR_TX_LIST_CNT; i++) {
		if (sc->vr_cdata.vr_tx_chain[i].vr_mbuf != NULL) {
			m_freem(sc->vr_cdata.vr_tx_chain[i].vr_mbuf);
			sc->vr_cdata.vr_tx_chain[i].vr_mbuf = NULL;
		}
	}

	bzero((char *)&sc->vr_ldata->vr_tx_list,
		sizeof (sc->vr_ldata->vr_tx_list));

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);

	return;
}

static struct vr_type *vr_lookup __P((struct pci_attach_args *));
static int vr_probe __P((struct device *, struct cfdata *, void *));
static void vr_attach __P((struct device *, struct device *, void *));
static void vr_shutdown __P((void *));

struct cfattach vr_ca = {
	sizeof (struct vr_softc), vr_probe, vr_attach
};

static struct vr_type *
vr_lookup(pa)
	struct pci_attach_args *pa;
{
	struct vr_type *vrt;

	for (vrt = vr_devs; vrt->vr_name != NULL; vrt++) {
		if (PCI_VENDOR(pa->pa_id) == vrt->vr_vid &&
		    PCI_PRODUCT(pa->pa_id) == vrt->vr_did)
			return (vrt);
	}
	return (NULL);
}

static int
vr_probe(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct pci_attach_args *pa = (struct pci_attach_args *)aux;

	if (vr_lookup(pa) != NULL)
		return (1);

	return (0);
}

/*
 * Stop all chip I/O so that the kernel's probe routines don't
 * get confused by errant DMAs when rebooting.
 */
static void vr_shutdown(arg)
	void *arg;
{
	struct vr_softc		*sc = (struct vr_softc *)arg;

	vr_stop(sc);

	return;
}

/*
 * Attach the interface. Allocate softc structures, do ifmedia
 * setup and ethernet/BPF attach.
 */
static void
vr_attach(parent, self, aux)
	struct device * const parent;
	struct device * const self;
	void * const aux;
{
#define	PCI_CONF_WRITE(r, v)	pci_conf_write(pa->pa_pc, pa->pa_tag, (r), (v))
#define	PCI_CONF_READ(r)	pci_conf_read(pa->pa_pc, pa->pa_tag, (r))
	struct vr_softc * const sc = (struct vr_softc *) self;
	struct pci_attach_args * const pa = (struct pci_attach_args *) aux;
	struct vr_type *vrt;
	int			i;
	u_int32_t		command;
	struct ifnet		*ifp;
	int			media = IFM_ETHER|IFM_100_TX|IFM_FDX;
	unsigned int		round;
	caddr_t			roundptr;
	u_char			eaddr[ETHER_ADDR_LEN];
	struct vr_type		*p;
	u_int16_t		phy_vid, phy_did, phy_sts;

	vrt = vr_lookup(pa);
	if (vrt == NULL) {
		printf("\n");
		panic("vr_attach: impossible");
	}

	printf(": %s Ethernet\n", vrt->vr_name);

	/*
	 * Handle power management nonsense.
	 */

	command = PCI_CONF_READ(VR_PCI_CAPID) & 0x000000FF;
	if (command == 0x01) {

		command = PCI_CONF_READ(VR_PCI_PWRMGMTCTRL);
		if (command & VR_PSTATE_MASK) {
			u_int32_t		iobase, membase, irq;

			/* Save important PCI config data. */
			iobase = PCI_CONF_READ(VR_PCI_LOIO);
			membase = PCI_CONF_READ(VR_PCI_LOMEM);
			irq = PCI_CONF_READ(VR_PCI_INTLINE);

			/* Reset the power state. */
			printf("%s: chip is in D%d power mode "
				"-- setting to D0\n",
				sc->vr_dev.dv_xname, command & VR_PSTATE_MASK);
			command &= 0xFFFFFFFC;
			PCI_CONF_WRITE(VR_PCI_PWRMGMTCTRL, command);

			/* Restore PCI config data. */
			PCI_CONF_WRITE(VR_PCI_LOIO, iobase);
			PCI_CONF_WRITE(VR_PCI_LOMEM, membase);
			PCI_CONF_WRITE(VR_PCI_INTLINE, irq);
		}
	}

	/*
	 * Map control/status registers.
	 */
	command = PCI_CONF_READ(PCI_COMMAND_STATUS_REG);
	command |= (PCI_COMMAND_IO_ENABLE |
		    PCI_COMMAND_MEM_ENABLE |
		    PCI_COMMAND_MASTER_ENABLE);
	PCI_CONF_WRITE(PCI_COMMAND_STATUS_REG, command);
	command = PCI_CONF_READ(PCI_COMMAND_STATUS_REG);

	{
		bus_space_tag_t iot, memt;
		bus_space_handle_t ioh, memh;
		int ioh_valid, memh_valid;
		pci_intr_handle_t intrhandle;
		const char *intrstr;

		ioh_valid = (pci_mapreg_map(pa, VR_PCI_LOIO,
			PCI_MAPREG_TYPE_IO, 0,
			&iot, &ioh, NULL, NULL) == 0);
		memh_valid = (pci_mapreg_map(pa, VR_PCI_LOMEM,
			PCI_MAPREG_TYPE_MEM |
			PCI_MAPREG_MEM_TYPE_32BIT,
			0, &memt, &memh, NULL, NULL) == 0);
#if defined(VR_USEIOSPACE)
		if (ioh_valid) {
			sc->vr_btag = iot;
			sc->vr_bhandle = ioh;
		} else if (memh_valid) {
			sc->vr_btag = memt;
			sc->vr_bhandle = memh;
		}
#else
		if (memh_valid) {
			sc->vr_btag = memt;
			sc->vr_bhandle = memh;
		} else if (ioh_valid) {
			sc->vr_btag = iot;
			sc->vr_bhandle = ioh;
		}
#endif
		else {
			printf(": unable to map device registers\n");
			return;
		}

		/* Allocate interrupt */
		if (pci_intr_map(pa->pa_pc, pa->pa_intrtag, pa->pa_intrpin,
				pa->pa_intrline, &intrhandle)) {
			printf("%s: couldn't map interrupt\n",
				sc->vr_dev.dv_xname);
			goto fail;
		}
		intrstr = pci_intr_string(pa->pa_pc, intrhandle);
		sc->vr_ih = pci_intr_establish(pa->pa_pc, intrhandle, IPL_NET,
						(void *)vr_intr, sc);
		if (sc->vr_ih == NULL) {
			printf("%s: couldn't establish interrupt",
				sc->vr_dev.dv_xname);
			if (intrstr != NULL)
				printf(" at %s", intrstr);
			printf("\n");
		}
		printf("%s: interrupting at %s\n",
			sc->vr_dev.dv_xname, intrstr);
	}
	sc->vr_ats = shutdownhook_establish(vr_shutdown, sc);
	if (sc->vr_ats == NULL)
		printf("%s: warning: couldn't establish shutdown hook\n",
			sc->vr_dev.dv_xname);

	/* Reset the adapter. */
	vr_reset(sc);

	/*
	 * Get station address. The way the Rhine chips work,
	 * you're not allowed to directly access the EEPROM once
	 * they've been programmed a special way. Consequently,
	 * we need to read the node address from the PAR0 and PAR1
	 * registers.
	 */
	VR_SETBIT(sc, VR_EECSR, VR_EECSR_LOAD);
	DELAY(200);
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		eaddr[i] = CSR_READ_1(sc, VR_PAR0 + i);

	/*
	 * A Rhine chip was detected. Inform the world.
	 */
	printf("%s: Ethernet address: %s\n",
		sc->vr_dev.dv_xname, ether_sprintf(eaddr));

	bcopy(eaddr, sc->vr_enaddr, ETHER_ADDR_LEN);

	sc->vr_ldata_ptr = malloc(sizeof (struct vr_list_data) + 8,
				M_DEVBUF, M_NOWAIT);
	if (sc->vr_ldata_ptr == NULL) {
		free(sc, M_DEVBUF);
		printf("%s: no memory for list buffers!\n",
			sc->vr_dev.dv_xname);
		return;
	}

	sc->vr_ldata = (struct vr_list_data *)sc->vr_ldata_ptr;
	round = (unsigned long)sc->vr_ldata_ptr & 0xF;
	roundptr = sc->vr_ldata_ptr;
	for (i = 0; i < 8; i++) {
		if (round % 8) {
			round++;
			roundptr++;
		} else
			break;
	}
	sc->vr_ldata = (struct vr_list_data *)roundptr;
	bzero(sc->vr_ldata, sizeof (struct vr_list_data));

	ifp = &sc->vr_ec.ec_if;
	ifp->if_softc = sc;
	ifp->if_mtu = ETHERMTU;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = vr_ioctl;
	ifp->if_output = ether_output;
	ifp->if_start = vr_start;
	ifp->if_watchdog = vr_watchdog;
	ifp->if_baudrate = 10000000;
	bcopy(sc->vr_dev.dv_xname, ifp->if_xname, IFNAMSIZ);

	for (i = VR_PHYADDR_MIN; i < VR_PHYADDR_MAX + 1; i++) {
		sc->vr_phy_addr = i;
		vr_phy_writereg(sc, PHY_BMCR, PHY_BMCR_RESET);
		DELAY(500);
		while (vr_phy_readreg(sc, PHY_BMCR)
				& PHY_BMCR_RESET);
		if ((phy_sts = vr_phy_readreg(sc, PHY_BMSR)))
			break;
	}
	if (phy_sts) {
		phy_vid = vr_phy_readreg(sc, PHY_VENID);
		phy_did = vr_phy_readreg(sc, PHY_DEVID);
		p = vr_phys;
		while (p->vr_vid) {
			if (phy_vid == p->vr_vid &&
				(phy_did | 0x000F) == p->vr_did) {
				sc->vr_pinfo = p;
				break;
			}
			p++;
		}
		if (sc->vr_pinfo == NULL)
			sc->vr_pinfo = &vr_phys[PHY_UNKNOWN];
	} else {
		printf("%s: MII without any phy!\n",
			sc->vr_dev.dv_xname);
		goto fail;
	}

	/*
	 * Do ifmedia setup.
	 */
	ifmedia_init(&sc->ifmedia, 0, vr_ifmedia_upd, vr_ifmedia_sts);

	vr_getmode_mii(sc);
	vr_autoneg_mii(sc, VR_FLAG_FORCEDELAY, 1);
	media = sc->ifmedia.ifm_media;
	vr_stop(sc);

	ifmedia_set(&sc->ifmedia, media);

	/*
	 * Call MI attach routines.
	 */
	if_attach(ifp);
	ether_ifattach(ifp, sc->vr_enaddr);

#if NBPFILTER > 0
	bpfattach(&sc->vr_ec.ec_if.if_bpf,
		ifp, DLT_EN10MB, sizeof (struct ether_header));
#endif

	sc->vr_ats = shutdownhook_establish(vr_shutdown, sc);
	if (sc->vr_ats == NULL)
		printf("%s: warning: couldn't establish shutdown hook\n",
			sc->vr_dev.dv_xname);

fail:
	return;
}
