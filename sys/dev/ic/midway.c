/*	$NetBSD: midway.c,v 1.5 1996/06/29 20:00:46 chuck Exp $	*/
/*	(sync'd to midway.c 1.55)	*/

/*
 *
 * Copyright (c) 1996 Charles D. Cranor and Washington University.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Charles D. Cranor and
 *	Washington University.
 * 4. The name of the author may not be used to endorse or promote products
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

/*
 *
 * m i d w a y . c   e n i 1 5 5   d r i v e r 
 *
 * author: Chuck Cranor <chuck@ccrc.wustl.edu>
 * started: spring, 1996 (written from scratch).
 *
 * notes from the author:
 *   Extra special thanks go to Werner Almesberger, EPFL LRC.   Werner's
 *   ENI driver was especially useful in figuring out how this card works.
 *   I would also like to thank Werner for promptly answering email and being
 *   generally helpful.
 */


#undef	EN_DEBUG
#undef	EN_DEBUG_RANGE		/* check ranges on en_read/en_write's? */
#define	EN_MBUF_OPT		/* try and put more stuff in mbuf? */
#define	EN_DIAG
#define	EN_STAT
#ifndef EN_DMA
#define EN_DMA		1	/* use dma? */
#endif
#define EN_NOTXDMA	0	/* hook to disable tx dma only */
#define EN_NORXDMA	0	/* hook to disable rx dma only */
#define EN_NOWMAYBE	1	/* hook to disable word maybe DMA */
				/* XXX: WMAYBE doesn't work, needs debugging */
#define EN_DDBHOOK	1	/* compile in ddb functions */

#if defined(DIAGNOSTIC) && !defined(EN_DIAG)
#define EN_DIAG			/* link in with master DIAG option */
#endif
#ifdef EN_STAT
#define EN_COUNT(X) (X)++
#else
#define EN_COUNT(X) /* nothing */
#endif

#ifdef EN_DEBUG
#undef	EN_DDBHOOK
#define	EN_DDBHOOK	1
#define STATIC /* nothing */
#define INLINE /* nothing */
#else /* EN_DEBUG */
#define STATIC static
#define INLINE inline
#endif /* EN_DEBUG */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/device.h>
#include <sys/ioctl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>
#include <net/if_atm.h>

#include <vm/vm.h>

#ifdef INET
#include <netinet/if_atm.h>
#endif

#ifdef NATM
#include <netinet/in.h>
#include <netnatm/natm.h>
#endif


#ifndef sparc
#include <machine/bus.h>
#endif

#include <dev/ic/midwayreg.h>
#include <dev/ic/midwayvar.h>

/*
 * params
 */

#ifndef EN_TXHIWAT
#define EN_TXHIWAT	(32*1024)	/* max 32 KB waiting to be DMAd out */
#endif

#ifndef EN_MINDMA
#define EN_MINDMA	64	/* don't DMA anything less than this (bytes) */
#endif

#define RX_NONE		0xffff	/* recv VC not in use */

#define EN_OBHDR	ATM_PH_DRIVER7  /* TBD in first mbuf ! */
#define EN_OBTRL	ATM_PH_DRIVER8  /* PDU trailier in last mbuf ! */

#define ENOTHER_FREE	0x01		/* free rxslot */
#define ENOTHER_DRAIN	0x02		/* almost free (drain DRQ dma) */
#define ENOTHER_RAW	0x04		/* 'raw' access  (aka boodi mode) */
#define ENOTHER_SWSL	0x08		/* in software service list */

int en_dma = EN_DMA;			/* use DMA (switch off for dbg) */

/*
 * autoconfig attachments
 */

struct cfdriver en_cd = {
    0, "en", DV_IFNET,
};

/*
 * local structures
 */

/*
 * params to en_txlaunch() function
 */

struct en_launch {
  u_int32_t tbd1;		/* TBD 1 */
  u_int32_t tbd2;		/* TBD 2 */
  u_int32_t pdu1;		/* PDU 1 (aal5) */
  int nodma;			/* don't use DMA */
  int need;			/* total space we need (pad out if less data) */
  int mlen;			/* length of mbuf (for dtq) */
  struct mbuf *t;		/* data */
  u_int32_t aal;		/* aal code */
  u_int32_t atm_vci;		/* vci */
  u_int8_t atm_flags;		/* flags */
};


/*
 * dma table (index by # of words)
 *
 * plan A: use WMAYBE
 * plan B: avoid WMAYBE
 */

struct en_dmatab {
  u_int8_t bcode;		/* code */
  u_int8_t divshift;		/* byte divisor */
};

static struct en_dmatab en_dma_planA[] = {
  { 0, 0 },		/* 0 */		{ MIDDMA_WORD, 2 },	/* 1 */
  { MIDDMA_2WORD, 3},	/* 2 */		{ MIDDMA_4WMAYBE, 2},	/* 3 */
  { MIDDMA_4WORD, 4},	/* 4 */		{ MIDDMA_8WMAYBE, 2},	/* 5 */
  { MIDDMA_8WMAYBE, 2},	/* 6 */		{ MIDDMA_8WMAYBE, 2},	/* 7 */
  { MIDDMA_8WORD, 5},   /* 8 */		{ MIDDMA_16WMAYBE, 2},	/* 9 */
  { MIDDMA_16WMAYBE,2},	/* 10 */	{ MIDDMA_16WMAYBE, 2},	/* 11 */
  { MIDDMA_16WMAYBE,2},	/* 12 */	{ MIDDMA_16WMAYBE, 2},	/* 13 */
  { MIDDMA_16WMAYBE,2},	/* 14 */	{ MIDDMA_16WMAYBE, 2},	/* 15 */
  { MIDDMA_16WORD, 6},  /* 16 */
};

static struct en_dmatab en_dma_planB[] = {
  { 0, 0 },		/* 0 */		{ MIDDMA_WORD, 2},	/* 1 */
  { MIDDMA_2WORD, 3},	/* 2 */		{ MIDDMA_WORD, 2},	/* 3 */
  { MIDDMA_4WORD, 4},	/* 4 */		{ MIDDMA_WORD, 2},	/* 5 */
  { MIDDMA_2WORD, 3},	/* 6 */		{ MIDDMA_WORD, 2},	/* 7 */
  { MIDDMA_8WORD, 5},   /* 8 */		{ MIDDMA_WORD, 2},	/* 9 */
  { MIDDMA_2WORD, 3},	/* 10 */	{ MIDDMA_WORD, 2},	/* 11 */
  { MIDDMA_4WORD, 4},	/* 12 */	{ MIDDMA_WORD, 2},	/* 13 */
  { MIDDMA_2WORD, 3},	/* 14 */	{ MIDDMA_WORD, 2},	/* 15 */
  { MIDDMA_16WORD, 6},  /* 16 */
};

static struct en_dmatab *en_dmaplan = en_dma_planA;
  
/*
 * macros/inline
 */

#ifdef EN_DEBUG_RANGE
u_int32_t en_read(sc, r)

struct en_softc *sc;
u_int32_t r;

{
  if (r > MID_MAXOFF || (r % 4)) {
    printf("en_read out of range, r=0x%x\n", r);
    panic("en_read");
  }
  return(bus_mem_read_4(sc->en_bc, sc->en_base, r));
}
#define EN_READ(SC,R) ntohl(en_read(SC,R))
#define EN_READDAT(SC,R) en_read(SC,R)

void en_write(sc, r, v)

struct en_softc *sc;
u_int32_t r, v;

{
  if (r > MID_MAXOFF || (r % 4)) {
    printf("en_write out of range, r=0x%x\n", r);
    panic("en_write");
  }
  bus_mem_write_4(sc->en_bc, sc->en_base, r, v);
}
#define EN_WRITE(SC,R,V) en_write(SC,R, htonl(V))
#define EN_WRITEDAT(SC,R,V) en_write(SC,R,V)

#else /* EN_DEBUG_RANGE */

#define EN_READ(SC,R) ntohl(bus_mem_read_4((SC)->en_bc, (SC)->en_base, (R)))
#define EN_WRITE(SC,R,V) \
	bus_mem_write_4((SC)->en_bc, (SC)->en_base, (R), htonl((V)))

#define EN_READDAT(SC,R) bus_mem_read_4((SC)->en_bc, (SC)->en_base, (R))
#define EN_WRITEDAT(SC,R,V) \
	bus_mem_write_4((SC)->en_bc, (SC)->en_base, (R), (V))

#define EN_WRAPADD(START,STOP,CUR,VAL) { \
	(CUR) = (CUR) + (VAL); \
	if ((CUR) >= (STOP)) \
		(CUR) = (START) + ((CUR) - (STOP)); \
	}
#endif /* EN_DEBUG_RANGE */

#define WORD_IDX(START, X) (((X) - (START)) / sizeof(u_int32_t))

/* we store sc->dtq and sc->drq data in the following format... */
#define EN_DQ_MK(SLOT,LEN) (((SLOT) << 20)|(LEN))
#define EN_DQ_SLOT(X) ((X) >> 20)
#define EN_DQ_LEN(X) ((X) & 0xfffff)

/* add an item to the DTQ (more to come) */
#define EN_DTQADD(SC,CNT,CHAN,BCODE,ADDR) \
	EN_DTQADD_XXX(SC,CNT,CHAN,BCODE,ADDR,0)

/* add a final item to the DTQ and kick it */
#define EN_DTQADDEND(SC,CNT,CHAN,BCODE,ADDR,LEN) { \
	(SC)->dtq[MID_DTQ_A2REG((SC)->dtq_us)] = EN_DQ_MK(CHAN,LEN); \
	EN_DTQADD_XXX(SC,CNT,CHAN,BCODE,ADDR,MID_DMA_END); \
	EN_WRITE((SC), MID_DMA_WRTX, MID_DTQ_A2REG((SC)->dtq_us)); \
}

/* DTQ add helper macro */
#define EN_DTQADD_XXX(SC,CNT,CHAN,BCODE,ADDR,END) { \
	EN_WRITE((SC), (SC)->dtq_us, \
		MID_MK_TXQ((CNT), (CHAN), (END), (BCODE))); \
	(SC)->dtq_us += 4; \
	EN_WRITE((SC), (SC)->dtq_us, (ADDR)); \
	EN_WRAPADD(MID_DTQOFF, MID_DTQEND, (SC)->dtq_us, 4); \
	(SC)->dtq_free--; \
}


/* add an item to the DRQ (more to come) */
#define EN_DRQADD(SC,CNT,VCI,BCODE,ADDR) \
	EN_DRQADD_XXX(SC,CNT,VCI,BCODE,ADDR,0)

/* add a final item to the DRQ and kick it */
#define EN_DRQADDEND(SC,CNT,VCI,BCODE,ADDR,LEN,SLOT) { \
	(SC)->drq[MID_DRQ_A2REG((SC)->drq_us)] = EN_DQ_MK(SLOT,LEN); \
	EN_DRQADD_XXX(SC,CNT,VCI,BCODE,ADDR,MID_DMA_END); \
	EN_WRITE((SC), MID_DMA_WRRX, MID_DRQ_A2REG((SC)->drq_us)); \
}

/* DRQ add helper macro */
#define EN_DRQADD_XXX(SC,CNT,VCI,BCODE,ADDR,END) { \
	EN_WRITE((SC), (SC)->drq_us, \
		MID_MK_RXQ((CNT), (VCI), (END), (BCODE))); \
	(SC)->drq_us += 4; \
	EN_WRITE((SC), (SC)->drq_us, (ADDR)); \
	EN_WRAPADD(MID_DRQOFF, MID_DRQEND, (SC)->drq_us, 4); \
	(SC)->drq_free--; \
}

/*
 * prototypes
 */

void	en_attach __P((struct en_softc *));
STATIC	int en_b2sz __P((int));
#ifdef EN_DEBUG
int	en_dump __P((int,int));
int	en_dumpmem __P((int,int,int));
#endif
STATIC	void en_dmaprobe __P((struct en_softc *));
STATIC	int en_dmaprobe_doit __P((struct en_softc *, u_int8_t *, 
							u_int8_t *, int));
STATIC	int en_dqneed __P((struct en_softc *, caddr_t, u_int));
STATIC	void en_init __P((struct en_softc *));
int	en_intr __P((void *));
STATIC	int en_ioctl __P((struct ifnet *, u_long, caddr_t));
STATIC	int en_k2sz __P((int));
STATIC	void en_loadvc __P((struct en_softc *, int));
STATIC	void en_mfix __P((struct en_softc *, struct mbuf *));
STATIC	struct mbuf *en_mget __P((struct en_softc *, u_int, u_int *));
STATIC	void en_reset __P((struct en_softc *));
STATIC	int en_rxctl __P((struct en_softc *, struct atm_pseudoioctl *, int));
STATIC	void en_txdma __P((struct en_softc *, int));
STATIC	void en_txlaunch __P((struct en_softc *, int, struct en_launch *));
STATIC	void en_service __P((struct en_softc *));
STATIC	void en_start __P((struct ifnet *));
STATIC	int en_sz2b __P((int));

/*
 * the driver code
 *
 * the code is arranged in a specific way:
 * [1] short/inline functions
 * [2] autoconfig stuff
 * [3] ioctl stuff
 * [4] reset -> init -> trasmit -> intr -> receive functions
 *
 */

/***********************************************************************/

/*
 * en_k2sz: convert KBytes to a size parameter (a log2)
 */

STATIC INLINE int en_k2sz(k)

int k;

{
  switch(k) {
    case 1:   return(0);
    case 2:   return(1);
    case 4:   return(2);
    case 8:   return(3);
    case 16:  return(4);
    case 32:  return(5);
    case 64:  return(6);
    case 128: return(7);
    default: panic("en_k2sz");
  }
  return(0);
}
#define en_log2(X) en_k2sz(X)


/*
 * en_b2sz: convert a DMA burst code to its byte size
 */

STATIC INLINE int en_b2sz(b)

int b;

{
  switch (b) {
    case MIDDMA_WORD:   return(1*4);
    case MIDDMA_2WMAYBE:
    case MIDDMA_2WORD:  return(2*4);
    case MIDDMA_4WMAYBE:
    case MIDDMA_4WORD:  return(4*4);
    case MIDDMA_8WMAYBE:
    case MIDDMA_8WORD:  return(8*4);
    case MIDDMA_16WMAYBE:
    case MIDDMA_16WORD: return(16*4);
    default: panic("en_k2sz");
  }
  return(0);
}


/*
 * en_sz2b: convert a burst size (bytes) to DMA burst code
 */

STATIC INLINE int en_sz2b(sz)

int sz;

{
  switch (sz) {
    case 1*4:  return(MIDDMA_WORD);
    case 2*4:  return(MIDDMA_2WORD);
    case 4*4:  return(MIDDMA_4WORD);
    case 8*4:  return(MIDDMA_8WORD);
    case 16*4: return(MIDDMA_16WORD);
    default: panic("en_k2sz");
  }
  return(0);
}


/*
 * en_dqneed: calculate number of DTQ/DRQ's needed for a buffer
 */

STATIC INLINE int en_dqneed(sc, data, len)

struct en_softc *sc;
caddr_t data;
u_int len;

{
  int result = 0, needalign;
    
    if (len < EN_MINDMA) {
      return(1);		/* will copy/DMA_JK */
    }

    if (sc->alburst) {
      needalign = (((u_int) data) & sc->bestburstmask);
      if (needalign) {
	result++;		/* alburst */
	len = len - (sc->bestburstlen - needalign);
      }
    }

    if (len)
      result++;			/* best shot */
    
    if (len > sc->bestburstlen && (len & sc->bestburstmask) != 0)
      result++;			/* clean up */

    return(result);
}


/*
 * en_mget: get an mbuf chain that can hold totlen bytes and return it
 * (for recv)   [based on am7990_get from if_le and ieget from if_ie]
 * after this call the sum of all the m_len's in the chain will be totlen.
 */

STATIC INLINE struct mbuf *en_mget(sc, totlen, drqneed)

struct en_softc *sc;
u_int totlen, *drqneed;

{
  struct mbuf *m;
  struct mbuf *top, **mp;
  *drqneed = 0;

  MGETHDR(m, M_DONTWAIT, MT_DATA);
  if (m == NULL)
    return(NULL);
  m->m_pkthdr.rcvif = &sc->enif;
  m->m_pkthdr.len = totlen;
  m->m_len = MHLEN;
  top = NULL;
  mp = &top;
  
  /* if (top != NULL) then we've already got 1 mbuf on the chain */
  while (totlen > 0) {
    if (top) {
      MGET(m, M_DONTWAIT, MT_DATA);
      if (!m) {
	m_freem(top);	
	return(NULL);	/* out of mbufs */
      }
      m->m_len = MLEN;
    }
    if (top && totlen >= MINCLSIZE) {
      MCLGET(m, M_DONTWAIT);
      if (m->m_flags & M_EXT)
	m->m_len = MCLBYTES;
    }
    m->m_len = min(totlen, m->m_len);
    totlen -= m->m_len;
    *mp = m;
    mp = &m->m_next;

    *drqneed += en_dqneed(sc, m->m_data, m->m_len);

  }
  return(top);
}

/***********************************************************************/

/*
 * autoconfig stuff
 */

void en_attach(sc)

struct en_softc *sc;

{
  struct ifnet *ifp = &sc->enif;
  bus_mem_addr_t membase;
  const char *intrstr;
  int retval, sz;
  u_int32_t reg, lcv, check, ptr, sav, midvloc;

  /*
   * probe card to determine memory size.   the stupid ENI card always
   * reports to PCI that it needs 4MB of space (2MB regs and 2MB RAM).
   * if it has less than 2MB RAM the addresses wrap in the RAM address space.
   * (i.e. on a 512KB card addresses 0x3ffffc, 0x37fffc, and 0x2ffffc
   * are aliases for 0x27fffc  [note that RAM starts at offset 0x200000]).
   */

  EN_WRITE(sc, MID_RESID, 0x0);	/* reset card before touching RAM */
  for (lcv = MID_PROBEOFF; lcv <= MID_MAXOFF ; lcv += MID_PROBSIZE) {
    EN_WRITE(sc, lcv, lcv);	/* data[address] = address */
    for (check = MID_PROBEOFF ; check < lcv ; check += MID_PROBSIZE) {
      reg = EN_READ(sc, check);
      if (reg != check) {		/* found an alias! */
	lcv -= MID_PROBSIZE;		/* take one step back */
	goto done_probe;		/* and quit */
      }
    }
  }
done_probe:
  sc->en_obmemsz = (lcv + 4) - MID_RAMOFF;

  /*
   * determine the largest DMA burst supported
   */

  en_dmaprobe(sc);

  /*
   * "hello world"
   */

  EN_WRITE(sc, MID_RESID, 0x0);		/* reset */
  for (lcv = MID_RAMOFF ; lcv < MID_RAMOFF + sc->en_obmemsz ; lcv += 4)
    EN_WRITE(sc, lcv, 0);	/* zero memory */

  reg = EN_READ(sc, MID_RESID);

  printf("%s: ATM midway v%d, board IDs %d.%d, %s%s%s, %dKB on-board RAM\n",
	sc->sc_dev.dv_xname, MID_VER(reg), MID_MID(reg), MID_DID(reg), 
	(MID_IS_SABRE(reg)) ? "sabre controller, " : "",
	(MID_IS_SUNI(reg)) ? "SUNI" : "Utopia",
	(!MID_IS_SUNI(reg) && MID_IS_UPIPE(reg)) ? " (pipelined)" : "",
	sc->en_obmemsz / 1024);
  printf("%s: maximum DMA burst length = %d bytes%s\n", sc->sc_dev.dv_xname,
	sc->bestburstlen, (sc->alburst) ? " (must align)" : "");
#if 0		/* WMAYBE doesn't work, don't complain about it */
  /* check if en_dmaprobe disabled wmaybe */
  if (en_dmaplan == en_dma_planB)
    printf("%s: note: WMAYBE DMA has been disabled\n", sc->sc_dev.dv_xname);
#endif

  /*
   * link into network subsystem and prepare card
   */

  bcopy(sc->sc_dev.dv_xname, sc->enif.if_xname, IFNAMSIZ);
  sc->enif.if_softc = sc;
  ifp->if_flags = IFF_SIMPLEX|IFF_NOTRAILERS;
  ifp->if_ioctl = en_ioctl;
  ifp->if_output = atm_output;
  ifp->if_start = en_start;

  /*
   * init softc
   */

  for (lcv = 0 ; lcv < MID_N_VC ; lcv++) {
    sc->rxvc2slot[lcv] = RX_NONE;
    sc->txspeed[lcv] = 0; /* full */
  }

  sz = sc->en_obmemsz - (MID_BUFOFF - MID_RAMOFF);
  ptr = sav = MID_BUFOFF;
  ptr = roundup(ptr, EN_TXSZ * 1024);	/* align */
  sz = sz - (ptr - sav);
  if (EN_TXSZ*1024 * EN_NTX > sz) {
    printf("%s: EN_NTX/EN_TXSZ too big\n", sc->sc_dev.dv_xname);
    return;
  }
  for (lcv = 0 ; lcv < EN_NTX ; lcv++) {
    sc->txslot[lcv].mbsize = 0;
    sc->txslot[lcv].start = ptr;
    ptr += (EN_TXSZ * 1024);
    sz -= (EN_TXSZ * 1024);
    sc->txslot[lcv].stop = ptr;
    bzero(&sc->txslot[lcv].indma, sizeof(sc->txslot[lcv].indma));
    bzero(&sc->txslot[lcv].q, sizeof(sc->txslot[lcv].q));
#ifdef EN_DEBUG
    printf("%s: tx%d: start 0x%x, stop 0x%x\n", sc->sc_dev.dv_xname, lcv,
		sc->txslot[lcv].start, sc->txslot[lcv].stop);
#endif
  }

  sav = ptr;
  ptr = roundup(ptr, EN_RXSZ * 1024);	/* align */
  sz = sz - (ptr - sav);
  sc->en_nrx = sz / (EN_RXSZ * 1024);
  if (sc->en_nrx <= 0) {
    printf("%s: EN_NTX/EN_TXSZ/EN_RXSZ too big\n", sc->sc_dev.dv_xname);
    return;
  }
  for (lcv = 0 ; lcv < sc->en_nrx ; lcv++) {
    sc->rxslot[lcv].rxhand = NULL;
    sc->rxslot[lcv].oth_flags = ENOTHER_FREE;
    bzero(&sc->rxslot[lcv].indma, sizeof(sc->rxslot[lcv].indma));
    bzero(&sc->rxslot[lcv].q, sizeof(sc->rxslot[lcv].q));
    midvloc = sc->rxslot[lcv].start = ptr;
    ptr += (EN_RXSZ * 1024);
    sz -= (EN_RXSZ * 1024);
    sc->rxslot[lcv].stop = ptr;
    midvloc = (midvloc & ~((EN_RXSZ*1024) - 1)) >> 2; /* mask, cvt to words */
    midvloc = midvloc >> MIDV_LOCTOPSHFT;  /* we only want the top 11 bits */
    midvloc = (midvloc & MIDV_LOCMASK) << MIDV_LOCSHIFT;
    sc->rxslot[lcv].mode = midvloc | 
	(en_k2sz(EN_RXSZ) << MIDV_SZSHIFT) | MIDV_TRASH;

#ifdef EN_DEBUG
    printf("%s: rx%d: start 0x%x, stop 0x%x, mode 0x%x\n", sc->sc_dev.dv_xname,
	lcv, sc->rxslot[lcv].start, sc->rxslot[lcv].stop, sc->rxslot[lcv].mode);
#endif
  }

#ifdef EN_STAT
  sc->vtrash = sc->otrash = sc->mfix = sc->txmbovr = sc->dmaovr = 0;
  sc->txoutspace = sc->txdtqout = sc->launch = sc->lheader = sc->ltail = 0;
  sc->hwpull = sc->swadd = sc->rxqnotus = sc->rxqus = sc->rxoutboth = 0;
  sc->rxdrqout = sc->ttrash = sc->rxmbufout = 0;
#endif
  sc->need_drqs = sc->need_dtqs = 0;

  printf("%s: %d %dKB receive buffers, %d %dKB transmit buffers allocated\n",
	sc->sc_dev.dv_xname, sc->en_nrx, EN_RXSZ, EN_NTX, EN_TXSZ);

  /*
   * final commit
   */

  if_attach(ifp);
  atm_ifattach(ifp); 

}


/*
 * en_dmaprobe: helper function for en_attach.
 *
 * see how the card handles DMA by running a few DMA tests.   we need
 * to figure out the largest number of bytes we can DMA in one burst
 * ("bestburstlen"), and if the starting address for a burst needs to
 * be aligned on any sort of boundary or not ("alburst").
 *
 * typical findings:
 * sparc1: bestburstlen=4, alburst=0 (ick, broken DMA!)
 * sparc2: bestburstlen=64, alburst=1
 * p166:   bestburstlen=64, alburst=0 
 */

STATIC void en_dmaprobe(sc)

struct en_softc *sc;

{
  u_int32_t srcbuf[64], dstbuf[64];
  u_int8_t *sp, *dp;
  int bestalgn, bestnotalgn, lcv, try, fail;

  sc->alburst = 0;

  sp = (u_int8_t *) srcbuf;
  while ((((u_int) sp) % MIDDMA_MAXBURST) != 0)
    sp += 4;
  dp = (u_int8_t *) dstbuf;
  while ((((u_int) dp) % MIDDMA_MAXBURST) != 0)
    dp += 4;

  bestalgn = bestnotalgn = en_dmaprobe_doit(sc, sp, dp, 0);

  for (lcv = 4 ; lcv < MIDDMA_MAXBURST ; lcv += 4) {
    try = en_dmaprobe_doit(sc, sp+lcv, dp+lcv, 0);
    if (try < bestnotalgn)
      bestnotalgn = try;
  }

  if (bestalgn != bestnotalgn) 		/* need bursts aligned */
    sc->alburst = 1;

  sc->bestburstlen = bestalgn;
  sc->bestburstshift = en_log2(bestalgn);
  sc->bestburstmask = sc->bestburstlen - 1; /* must be power of 2 */
  sc->bestburstcode = en_sz2b(bestalgn);

  if (sc->bestburstlen <= 2*sizeof(u_int32_t))
    return;				/* won't be using WMAYBE */

  /*
   * test that WMAYBE dma works like we think it should 
   * (i.e. no alignment restrictions on host address other than alburst)
   */

  try = sc->bestburstlen - 4;
  fail = 0;
  fail += en_dmaprobe_doit(sc, sp, dp, try);
  for (lcv = 4 ; lcv < sc->bestburstlen ; lcv += 4) {
    fail += en_dmaprobe_doit(sc, sp+lcv, dp+lcv, try);
    if (sc->alburst)
      try -= 4;
  }
  if (EN_NOWMAYBE || fail) {
    if (fail)
      printf("%s: WARNING: WMAYBE DMA test failed %d time(s)\n", 
	sc->sc_dev.dv_xname, fail);
    en_dmaplan = en_dma_planB;		/* fall back to plan B */
  }

}


/*
 * en_dmaprobe_doit: do actual testing
 */

en_dmaprobe_doit(sc, sp, dp, wmtry)

struct en_softc *sc;
u_int8_t *sp, *dp;
int wmtry;

{
  int lcv, retval = 4, cnt, count;
  u_int32_t reg, bcode, midvloc;

  /*
   * set up a 1k buffer at MID_BUFOFF
   */

  EN_WRITE(sc, MID_RESID, 0x0);	/* reset card before touching RAM */

  for (lcv = MID_BUFOFF ; lcv < 1024; lcv += 4) 
    EN_WRITE(sc, lcv, 0);	/* zero memory */

  midvloc = (MID_BUFOFF / sizeof(u_int32_t)) >> MIDV_LOCTOPSHFT;
  EN_WRITE(sc, MIDX_PLACE(0), MIDX_MKPLACE(en_k2sz(1), midvloc));
  EN_WRITE(sc, MID_VC(0), (midvloc << MIDV_LOCSHIFT) 
		| (en_k2sz(1) << MIDV_SZSHIFT) | MIDV_TRASH);
  EN_WRITE(sc, MID_DST_RP(0), 0);
  EN_WRITE(sc, MID_WP_ST_CNT(0), 0);

  for (lcv = 0 ; lcv < 68 ; lcv++) 		/* set up sample data */
    sp[lcv] = lcv+1;
  EN_WRITE(sc, MID_MAST_CSR, MID_MCSR_ENDMA);	/* enable DMA (only) */

  sc->drq_chip = MID_DRQ_REG2A(EN_READ(sc, MID_DMA_RDRX));
  sc->dtq_chip = MID_DTQ_REG2A(EN_READ(sc, MID_DMA_RDTX));

  /*
   * try it now . . .  DMA it out, then DMA it back in and compare
   *
   * note: in order to get the dma stuff to reverse directions it wants
   * the "end" flag set!   since we are not dma'ing valid data we may
   * get an ident mismatch interrupt (which we will ignore).
   *
   * note: we've got two different tests rolled up in the same loop
   * if (wmtry) 
   *   then we are doing a wmaybe test and wmtry is a byte count
   *   else we are doing a burst test
   */

  for (lcv = 8 ; lcv <= MIDDMA_MAXBURST ; lcv = lcv * 2) {
    if (wmtry) {
      count = (sc->bestburstlen - sizeof(u_int32_t)) / sizeof(u_int32_t);
      bcode = en_dmaplan[count].bcode;
      count = wmtry >> en_dmaplan[count].divshift;
    } else {
      bcode = en_sz2b(lcv);
      count = 1;
    }
    EN_WRITE(sc, sc->dtq_chip, MID_MK_TXQ(count, 0, MID_DMA_END, bcode));
    EN_WRITE(sc, sc->dtq_chip+4, vtophys(sp));
    EN_WRITE(sc, MID_DMA_WRTX, MID_DTQ_A2REG(sc->dtq_chip+8));
    cnt = 1000;
    while (EN_READ(sc, MID_DMA_RDTX) == MID_DTQ_A2REG(sc->dtq_chip)) {
      DELAY(1);
      cnt--;
      if (cnt == 0) {
	printf("%s: unexpected timeout in tx DMA test\n", sc->sc_dev.dv_xname);
	return(retval);		/* timeout, give up */
      }
    }
    EN_WRAPADD(MID_DTQOFF, MID_DTQEND, sc->dtq_chip, 8);
    reg = EN_READ(sc, MID_INTACK); 
    if ((reg & MID_INT_DMA_TX) != MID_INT_DMA_TX) {
      printf("%s: unexpected status in tx DMA test: 0x%x\n", 
		sc->sc_dev.dv_xname, reg);
      return(retval);
    }
    EN_WRITE(sc, MID_MAST_CSR, MID_MCSR_ENDMA);   /* re-enable DMA (only) */

    /* "return to sender..."  address is known ... */

    EN_WRITE(sc, sc->drq_chip, MID_MK_RXQ(count, 0, MID_DMA_END, bcode));
    EN_WRITE(sc, sc->drq_chip+4, vtophys(dp));
    EN_WRITE(sc, MID_DMA_WRRX, MID_DRQ_A2REG(sc->drq_chip+8));
    cnt = 1000;
    while (EN_READ(sc, MID_DMA_RDRX) == MID_DRQ_A2REG(sc->drq_chip)) {
      DELAY(1);
      cnt--;
      if (cnt == 0) {
	printf("%s: unexpected timeout in rx DMA test\n", sc->sc_dev.dv_xname);
	return(retval);		/* timeout, give up */
      }
    }
    EN_WRAPADD(MID_DRQOFF, MID_DRQEND, sc->drq_chip, 8);
    reg = EN_READ(sc, MID_INTACK); 
    if ((reg & MID_INT_DMA_RX) != MID_INT_DMA_RX) {
      printf("%s: unexpected status in rx DMA test: 0x%x\n", 
		sc->sc_dev.dv_xname, reg);
      return(retval);
    }
    EN_WRITE(sc, MID_MAST_CSR, MID_MCSR_ENDMA);   /* re-enable DMA (only) */

    if (wmtry) {
      return(bcmp(sp, dp, wmtry));  /* wmtry always exits here, no looping */
    }
  
    if (bcmp(sp, dp, lcv))
      return(retval);		/* failed, use last value */

    retval = lcv;

  }
  return(retval);		/* studly 64 byte DMA present!  oh baby!! */
}

/***********************************************************************/

/*
 * en_ioctl: handle ioctl requests
 */

STATIC int en_ioctl(ifp, cmd, data)

struct ifnet *ifp;
u_long cmd;
caddr_t data;

{
    struct en_softc *sc = (struct en_softc *) ifp->if_softc;
    struct ifaddr *ifa = (struct ifaddr *) data;
    struct ifreq *ifr = (struct ifreq *) data;
    struct atm_pseudoioctl *api = (struct atm_pseudoioctl *)data;
#ifdef NATM
    struct atm_rawioctl *ario = (struct atm_rawioctl *)data;
#endif
    int s, error = 0, slot;

    s = splnet();

    switch (cmd) {
	case SIOCATMENA:		/* enable circuit for recv */
		error = en_rxctl(sc, api, 1);
		break;

	case SIOCATMDIS: 		/* disable circuit for recv */
		error = en_rxctl(sc, api, 0);
		break;

#ifdef NATM
	case SIOCXRAWATM:
		if ((slot = sc->rxvc2slot[ario->npcb->npcb_vci]) == RX_NONE) {
			error = EINVAL;
			break;
		}
		if (ario->rawvalue)
			sc->rxslot[slot].oth_flags |= ENOTHER_RAW;
		else
			sc->rxslot[slot].oth_flags &= (~ENOTHER_RAW);
#ifdef EN_DEBUG
		printf("%s: rxvci%d: turn %s raw (boodi) mode\n",
			sc->sc_dev.dv_xname, ario->npcb->npcb_vci,
			(ario->rawvalue) ? "on" : "off");
#endif
		break;
#endif
	case SIOCSIFADDR: 
		ifp->if_flags |= IFF_UP;
#ifdef INET
		if (ifa->ifa_addr->sa_family == AF_INET) {
			en_reset(sc);
			en_init(sc);
			ifa->ifa_rtrequest = atm_rtrequest; /* ??? */
			break;
		}
#endif /* INET */
		/* what to do if not INET? */
		en_reset(sc);
		en_init(sc);
		break;

	case SIOCGIFADDR: 
		error = EINVAL;
		break;

	case SIOCSIFFLAGS: 
		error = EINVAL;
		break;

#if defined(SIOCSIFMTU)		/* ??? copied from if_de */
#if !defined(ifr_mtu)
#define ifr_mtu ifr_metric
#endif
	case SIOCSIFMTU:
	    /*
	     * Set the interface MTU.
	     */
#ifdef notsure
	    if (ifr->ifr_mtu > ATMMTU) {
		error = EINVAL;
		break;
	    }
#endif
	    ifp->if_mtu = ifr->ifr_mtu;
		/* XXXCDC: do we really need to reset on MTU size change? */
	    en_reset(sc);
	    en_init(sc);
	    break;
#endif /* SIOCSIFMTU */

	default: 
	    error = EINVAL;
	    break;
    }
    splx(s);
    return error;
}


/*
 * en_rxctl: turn on and off VCs for recv.
 */

STATIC int en_rxctl(sc, pi, on)

struct en_softc *sc;
struct atm_pseudoioctl *pi;
int on;

{
  u_int s, vci, flags, slot;
  u_int32_t oldmode, newmode;

  vci = ATM_PH_VCI(&pi->aph);
  flags = ATM_PH_FLAGS(&pi->aph);

#ifdef EN_DEBUG
  printf("%s: %s vpi=%d, vci=%d, flags=%d\n", sc->sc_dev.dv_xname,
	(on) ? "enable" : "disable", ATM_PH_VPI(&pi->aph), vci, flags);
#endif

  if (ATM_PH_VPI(&pi->aph) || vci >= MID_N_VC)
    return(EINVAL);

  /*
   * turn on VCI!
   */

  if (on) {
    if (sc->rxvc2slot[vci] != RX_NONE)
      return(EINVAL);
    for (slot = 0 ; slot < sc->en_nrx ; slot++)
      if (sc->rxslot[slot].oth_flags & ENOTHER_FREE)
	break;
    if (slot == sc->en_nrx)
      return(ENOSPC);
    sc->rxvc2slot[vci] = slot;
    sc->rxslot[slot].rxhand = NULL;
    oldmode = sc->rxslot[slot].mode;
    newmode = (flags & ATM_PH_AAL5) ? MIDV_AAL5 : MIDV_NOAAL;
    sc->rxslot[slot].mode = MIDV_SETMODE(oldmode, newmode);
    sc->rxslot[slot].atm_vci = vci;
    sc->rxslot[slot].atm_flags = flags;
    sc->rxslot[slot].oth_flags = 0;
    sc->rxslot[slot].rxhand = pi->rxhand;
    if (sc->rxslot[slot].indma.ifq_head || sc->rxslot[slot].q.ifq_head)
      panic("en_rxctl: left over mbufs on enable");
    en_loadvc(sc, vci);		/* does debug printf for us */
    return(0);
  }

  /*
   * turn off VCI
   */

  if (sc->rxvc2slot[vci] == RX_NONE)
    return(EINVAL);
  slot = sc->rxvc2slot[vci];
  if ((sc->rxslot[slot].oth_flags & (ENOTHER_FREE|ENOTHER_DRAIN)) != 0)
    return(EINVAL);
  s = splimp();		/* block out enintr() */
  oldmode = EN_READ(sc, MID_VC(vci));
  newmode = MIDV_SETMODE(oldmode, MIDV_TRASH);
  EN_WRITE(sc, MID_VC(vci), (newmode | (oldmode & MIDV_INSERVICE)));
		/* halt in tracks, be careful to preserve inserivce bit */
  DELAY(27);
  sc->rxslot[slot].rxhand = NULL;
  sc->rxslot[slot].mode = newmode;

  /* if stuff is still going on we are going to have to drain it out */
  if (sc->rxslot[slot].indma.ifq_head || 
		sc->rxslot[slot].q.ifq_head ||
		(oldmode & MIDV_INSERVICE) != 0 ||
		(sc->rxslot[slot].oth_flags & ENOTHER_SWSL) != 0) {
    sc->rxslot[slot].oth_flags |= ENOTHER_DRAIN;
  } else {
    sc->rxslot[slot].oth_flags = ENOTHER_FREE;
    sc->rxslot[slot].atm_vci = RX_NONE;
    sc->rxvc2slot[vci] = RX_NONE;
  }
  splx(s);		/* enable enintr() */
#ifdef EN_DEBUG
  printf("%s: rx%d: VCI %d is now %s\n", sc->sc_dev.dv_xname, slot, vci,
	(sc->rxslot[slot].oth_flags & ENOTHER_DRAIN) ? "draining" : "free");
#endif
  return(0);
}

/***********************************************************************/

/*
 * en_reset: reset the board, throw away work in progress.
 * must en_init to recover.
 */

STATIC void en_reset(sc)

struct en_softc *sc;

{
  struct mbuf *m;
  int lcv, slot;

#ifdef EN_DEBUG
  printf("%s: reset\n", sc->sc_dev.dv_xname);
#endif

  EN_WRITE(sc, MID_RESID, 0x0);	/* reset hardware */

  /*
   * recv: dump any mbufs we are dma'ing into, if DRAINing, then a reset
   * will free us!
   */

  for (lcv = 0 ; lcv < MID_N_VC ; lcv++) {
    if (sc->rxvc2slot[lcv] == RX_NONE)
      continue;
    slot = sc->rxvc2slot[lcv];
    while (1) {
      IF_DEQUEUE(&sc->rxslot[slot].indma, m);
      if (m == NULL) 
	break;		/* >>> exit 'while(1)' here <<< */
      m_freem(m);
    }
    while (1) {
      IF_DEQUEUE(&sc->rxslot[slot].q, m);
      if (m == NULL) 
	break;		/* >>> exit 'while(1)' here <<< */
      m_freem(m);
    }
    sc->rxslot[slot].oth_flags &= ~ENOTHER_SWSL;
    if (sc->rxslot[slot].oth_flags & ENOTHER_DRAIN) {
      sc->rxslot[slot].oth_flags = ENOTHER_FREE;
      sc->rxvc2slot[lcv] = RX_NONE;
#ifdef EN_DEBUG
  printf("%s: rx%d: VCI %d is now free\n", sc->sc_dev.dv_xname, slot, lcv);
#endif
    }
  }

  /*
   * xmit: dump everything
   */

  for (lcv = 0 ; lcv < EN_NTX ; lcv++) {
    while (1) {
      IF_DEQUEUE(&sc->txslot[lcv].indma, m);
      if (m == NULL) 
	break;		/* >>> exit 'while(1)' here <<< */
      m_freem(m);
    }
    while (1) {
      IF_DEQUEUE(&sc->txslot[lcv].q, m);
      if (m == NULL) 
	break;		/* >>> exit 'while(1)' here <<< */
      m_freem(m);
    }
    sc->txslot[lcv].mbsize = 0;
  }

  return;
}


/*
 * en_init: init board and sync the card with the data in the softc.
 */

STATIC void en_init(sc)

struct en_softc *sc;

{
  int vc, slot;
  u_int32_t reg, loc;

  if ((sc->enif.if_flags & IFF_UP) == 0) {
#ifdef EN_DEBUG
    printf("%s: going down\n", sc->sc_dev.dv_xname);
#endif
    en_reset(sc);			/* to be safe */
    sc->enif.if_flags &= ~IFF_RUNNING;	/* disable */
    return;
  }

#ifdef EN_DEBUG
  printf("%s: going up\n", sc->sc_dev.dv_xname);
#endif
  sc->enif.if_flags |= IFF_RUNNING;	/* enable */

  EN_WRITE(sc, MID_RESID, 0x0);		/* reset */

  /*
   * init obmem data structures: vc tab, dma q's, slist.
   */

  for (vc = 0 ; vc < MID_N_VC ; vc++) 
    en_loadvc(sc, vc);

  bzero(&sc->drq, sizeof(sc->drq));
  sc->drq_free = MID_DRQ_N;
  sc->drq_chip = MID_DRQ_REG2A(EN_READ(sc, MID_DMA_RDRX));
  EN_WRITE(sc, MID_DMA_WRRX, MID_DRQ_A2REG(sc->drq_chip)); 
						/* ensure zero queue */
  sc->drq_us = sc->drq_chip;

  bzero(&sc->dtq, sizeof(sc->dtq));
  sc->dtq_free = MID_DTQ_N;
  sc->dtq_chip = MID_DTQ_REG2A(EN_READ(sc, MID_DMA_RDTX));
  EN_WRITE(sc, MID_DMA_WRTX, MID_DRQ_A2REG(sc->dtq_chip)); 
						/* ensure zero queue */
  sc->dtq_us = sc->dtq_chip;

  sc->hwslistp = MID_SL_REG2A(EN_READ(sc, MID_SERV_WRITE));
  sc->swsl_size = sc->swsl_head = sc->swsl_tail = 0;

#ifdef EN_DEBUG
  printf("%s: drq free/chip: %d/0x%x, dtq free/chip: %d/0x%x, hwslist: 0x%x\n", 
    sc->sc_dev.dv_xname, sc->drq_free, sc->drq_chip, 
    sc->dtq_free, sc->dtq_chip, sc->hwslistp);
#endif

  for (slot = 0 ; slot < EN_NTX ; slot++) {
    sc->txslot[slot].bfree = EN_TXSZ * 1024;
    EN_WRITE(sc, MIDX_READPTR(slot), 0);
    EN_WRITE(sc, MIDX_DESCSTART(slot), 0);
    loc = sc->txslot[slot].cur = sc->txslot[slot].start;
    loc = (loc & ~((EN_TXSZ*1024) - 1)) >> 2; /* mask, cvt to words */
    loc = loc >> MIDV_LOCTOPSHFT;	/* top 11 bits */
    EN_WRITE(sc, MIDX_PLACE(slot), MIDX_MKPLACE(en_k2sz(EN_TXSZ), loc));
#ifdef EN_DEBUG
    printf("%s: tx%d: place 0x%x\n", sc->sc_dev.dv_xname,  slot,
	EN_READ(sc, MIDX_PLACE(slot)));
#endif
  }

  /*
   * enable!
   */

  EN_WRITE(sc, MID_INTENA, MID_INT_TX|MID_INT_DMA_OVR|MID_INT_IDENT|
	MID_INT_LERR|MID_INT_DMA_ERR|MID_INT_DMA_RX|MID_INT_DMA_TX|
	MID_INT_SERVICE| /* >>> MID_INT_SUNI| XXXCDC<<< */ MID_INT_STATS);
  EN_WRITE(sc, MID_MAST_CSR, MID_SETIPL(sc->ipl)|MID_MCSR_ENDMA|
	MID_MCSR_ENTX|MID_MCSR_ENRX);

}


/*
 * en_loadvc: load a vc tab entry from a slot
 */

STATIC void en_loadvc(sc, vc)

struct en_softc *sc;
int vc;

{
  int slot;
  u_int32_t reg = EN_READ(sc, MID_VC(vc));
  
  reg = MIDV_SETMODE(reg, MIDV_TRASH);
  EN_WRITE(sc, MID_VC(vc), reg);
  DELAY(27);

  if ((slot = sc->rxvc2slot[vc]) == RX_NONE)
    return;

  /* no need to set CRC */
  EN_WRITE(sc, MID_DST_RP(vc), 0);	/* read pointer = 0, desc. start = 0 */
  EN_WRITE(sc, MID_WP_ST_CNT(vc), 0);	/* write pointer = 0 */
  EN_WRITE(sc, MID_VC(vc), sc->rxslot[slot].mode);  /* set mode, size, loc */
  sc->rxslot[slot].cur = sc->rxslot[slot].start;

#ifdef EN_DEBUG
    printf("%s: rx%d: assigned to VCI %d\n", sc->sc_dev.dv_xname, slot, vc);
#endif
}


/*
 * en_start: start transmitting the next packet that needs to go out
 * if there is one.    note that atm_output() has already splimp()'d us.
 */

STATIC void en_start(ifp)

struct ifnet *ifp;

{
    struct en_softc *sc = (struct en_softc *) ifp->if_softc;
    struct ifqueue *ifq = &ifp->if_snd; /* if INPUT QUEUE */
    struct mbuf *m, *lastm;
    struct atm_pseudohdr *ap, *new_ap;
    int txchan, c, mlen, got, need, toadd, cellcnt;
    u_int32_t atm_vpi, atm_vci, atm_flags, *dat, aal;
    u_int8_t *cp;

    if ((ifp->if_flags & IFF_RUNNING) == 0)
	return;

    /*
     * remove everything from interface queue since we handle all queueing
     * locally ... 
     */

    while (1) {

      IF_DEQUEUE(ifq, m);
      if (m == NULL)
	return;		/* EMPTY: >>> exit here <<< */
    
      /*
       * calculate size of packet (in bytes)
       * we also eliminate all stupid (non-word) alignments here using
       * en_mfix().   a well behaved protocol will never need en_mfix()!
       * after this loop mlen total length of mbuf chain (including atm_ph),
       * and lastm is a pointer to the last mbuf on the chain.
       */

      lastm = m;
      mlen = 0;
      while (1) {
	if ( (mtod(lastm, u_int) % sizeof(u_int32_t)) != 0 ||
	  ((lastm->m_len % sizeof(u_int32_t)) != 0 && lastm->m_next))
	  en_mfix(sc, lastm);
	mlen += lastm->m_len;
	if (lastm->m_next == NULL)
	  break;
	lastm = lastm->m_next;
      }

      ap = mtod(m, struct atm_pseudohdr *);

      atm_vpi = ATM_PH_VPI(ap);
      atm_vci = ATM_PH_VCI(ap);
      atm_flags = ATM_PH_FLAGS(ap) & ~(EN_OBHDR|EN_OBTRL);
      aal = ((atm_flags & ATM_PH_AAL5) != 0) 
			? MID_TBD_AAL5 : MID_TBD_NOAAL5;

      /*
       * check that vpi/vci is one we can use
       */

      if (atm_vpi || atm_vci > MID_N_VC) {
	printf("%s: output vpi=%d, vci=%d out of card range, dropping...\n", 
		ifp->if_xname, atm_vpi, atm_vci);
	m_freem(m);
	continue;
      }

      /*
       * computing how much padding we need on the end of the mbuf, then
       * see if we can put the TBD at the front of the mbuf where the
       * link header goes (well behaved protocols will reserve room for us).
       * last, check if room for PDU tail.
       *
       * got = number of bytes of data we have
       * cellcnt = number of cells in this mbuf
       * need = number of bytes of data + padding we need (excludes TBD)
       * toadd = number of bytes of data we need to add to end of mbuf,
       *	[including AAL5 PDU, if AAL5]
       */

      got = mlen - sizeof(struct atm_pseudohdr *);
      toadd = (aal == MID_TBD_AAL5) ? MID_PDU_SIZE : 0;	/* PDU */
      cellcnt = (got + toadd + (MID_ATMDATASZ - 1)) / MID_ATMDATASZ;
      need = cellcnt * MID_ATMDATASZ;
      toadd = need - got;		/* recompute, including zero padding */

#ifdef EN_DEBUG
      printf("%s: txvci%d: mlen=%d, got=%d, need=%d, toadd=%d, cell#=%d\n",
	sc->sc_dev.dv_xname, atm_vci, mlen, got, need, toadd, cellcnt);
      printf("     leading_space=%d, trailing_space=%d\n", 
	M_LEADINGSPACE(m), M_TRAILINGSPACE(lastm));
#endif

#ifdef EN_MBUF_OPT
      if (M_LEADINGSPACE(m) >= MID_TBD_SIZE) {
	m->m_data -= MID_TBD_SIZE;
	m->m_len += MID_TBD_SIZE;
	mlen += MID_TBD_SIZE;
	new_ap = mtod(m, struct atm_pseudohdr *);
	*new_ap = *ap;			/* move it back */
	ap = new_ap;
	dat = ((u_int32_t *) ap) + 1;
	/* make sure the TBD is in proper byte order */
	*dat++ = htonl(MID_TBD_MK1(aal, sc->txspeed[atm_vci], cellcnt));
	*dat = htonl(MID_TBD_MK2(atm_vci, 0, 0));
	atm_flags |= EN_OBHDR;
      }

      if (toadd && M_TRAILINGSPACE(lastm) >= toadd) {
	cp = mtod(lastm, u_int8_t *) + lastm->m_len;
	lastm->m_len += toadd;
	mlen += toadd;
	if (aal == MID_TBD_AAL5) {
	  bzero(cp, toadd - MID_PDU_SIZE);
	  dat = (u_int32_t *)(cp + toadd - MID_PDU_SIZE);
	  /* make sure the PDU is in proper byte order */
	  *dat = htonl(MID_PDU_MK1(0, 0, got));
	} else {
	  bzero(cp, toadd);
	}
	atm_flags |= EN_OBTRL;
      }
#endif	/* EN_MBUF_OPT */
      ATM_PH_FLAGS(ap) = atm_flags;	/* update EN_OBHDR/EN_OBTRL bits */

      /*
       * choose channel with smallest # of bytes waiting for DMA
       */

      if (sc->txspeed[atm_vci]) {
	txchan = 1;
	for (c = 1 ; c < EN_NTX; c++) {
	  if (sc->txslot[c].mbsize < sc->txslot[txchan].mbsize)
	    txchan = c;
	  if (sc->txslot[txchan].mbsize == 0) break; /* zero length!!! */
	}
      } else {
	txchan = 0;
      }

      if (sc->txslot[txchan].mbsize > EN_TXHIWAT) {
	EN_COUNT(sc->txmbovr);
	m_freem(m);
#ifdef EN_DEBUG
	printf("%s: tx%d: buffer space shortage\n", ifp->if_xname,
		txchan);
#endif
	continue;
      }

      sc->txslot[txchan].mbsize += mlen;

#ifdef EN_DEBUG
      printf("%s: tx%d: VPI=%d, VCI=%d, FLAGS=0x%x, speed=0x%x\n",
	sc->sc_dev.dv_xname, txchan, atm_vpi, atm_vci, atm_flags, 
	sc->txspeed[atm_vci]);
      printf("     adjusted mlen=%d, mbsize=%d\n", mlen, 
		sc->txslot[txchan].mbsize);
#endif

      IF_ENQUEUE(&sc->txslot[txchan].q, m);
      en_txdma(sc, txchan);

  }
  /*NOTREACHED*/
}


/*
 * en_mfix: fix a stupid mbuf
 */

STATIC void en_mfix(sc, m)

struct en_softc *sc;
struct mbuf *m;

{
  u_char *d = mtod(m, u_char *), *cp;
  int off = ((u_int) d) % sizeof(u_int32_t);
  struct mbuf *nxt;

  EN_COUNT(sc->mfix);			/* count # of calls */
#ifdef EN_DEBUG
  printf("%s: mfix mbuf m_data=0x%x, m_len=%d\n", sc->sc_dev.dv_xname,
	m->m_data, m->m_len);
#endif

  if (off) {
    bcopy(d, d - off, m->m_len);   /* ALIGN! (with costly data copy...) */
    d -= off;
    m->m_data = (caddr_t)d;
  }

  off = m->m_len % sizeof(u_int32_t);
  if (off == 0)
    return;

  d = d + m->m_len;
  off = sizeof(u_int32_t) - off;
  
  nxt = m->m_next;
  while (off--) {
    for ( ; nxt != NULL && nxt->m_len == 0 ; nxt = nxt->m_next)
      /*null*/;
    if (nxt == NULL) {		/* out of data, zero fill */
      *d++ = 0;
      continue;			/* next "off" */
    }
    cp = mtod(nxt, u_char *);
    *d++ = *cp++;
    m->m_len++;
    nxt->m_len--; 
    nxt->m_data = (caddr_t)cp;
  }
  return;
}




/*
 * en_txdma: start trasmit DMA, if possible
 */

STATIC void en_txdma(sc, chan)

struct en_softc *sc;
int chan;

{
  struct mbuf *tmp;
  struct atm_pseudohdr *ap;
  struct en_launch launch;
  int datalen, dtqneed, len, ncells, needalign;
  u_int8_t *cp;

#ifdef EN_DEBUG
  printf("%s: tx%d: starting...\n", sc->sc_dev.dv_xname, chan);
#endif

again:
  launch.nodma = 0;

  /*
   * get an mbuf waiting for DMA
   */

  launch.t = sc->txslot[chan].q.ifq_head; /* peek at head of queue */

  if (launch.t == NULL) {
#ifdef EN_DEBUG
    printf("%s: tx%d: ...done!\n", sc->sc_dev.dv_xname, chan);
#endif
    return;	/* >>> exit here if no data waiting for DMA <<< */
  }

  /*
   * get flags, vci
   * 
   * note: launch.need = # bytes we need to get on the card
   *	   dtqneed = # of DTQs we need for this packet
   *       launch.mlen = # of bytes in in mbuf chain (<= launch.need)
   */

  ap = mtod(launch.t, struct atm_pseudohdr *);
  launch.atm_vci = ATM_PH_VCI(ap);
  launch.atm_flags = ATM_PH_FLAGS(ap);
  launch.aal = ((launch.atm_flags & ATM_PH_AAL5) != 0) ? 
		MID_TBD_AAL5 : MID_TBD_NOAAL5;

  /*
   * XXX: have to recompute the length again, even though we already did
   * it in en_start().   might as well compute dtqneed here as well, so 
   * this isn't that bad.
   */

  if ((launch.atm_flags & EN_OBHDR) == 0) {
    dtqneed = 1;		/* header still needs to be added */
    launch.need = MID_TBD_SIZE;	/* not includeded with mbuf */
  } else {
    dtqneed = 0;		/* header on-board, dma with mbuf */
    launch.need = 0;
  }

  launch.mlen = 0;
  for (tmp = launch.t ; tmp != NULL ; tmp = tmp->m_next) {
    len = tmp->m_len;
    launch.mlen += len;
    cp = mtod(tmp, u_int8_t *);
    if (tmp == launch.t) {
      len -= sizeof(struct atm_pseudohdr); /* don't count this! */
      cp += sizeof(struct atm_pseudohdr);
    }
    launch.need += len;
    if (len == 0)
      continue;			/* atm_pseudohdr alone in first mbuf */

    dtqneed += en_dqneed(sc, (caddr_t) cp, len);
  }

  if ((launch.atm_flags & EN_OBTRL) == 0) {
    if (launch.aal == MID_TBD_AAL5) {
      datalen = launch.need - MID_TBD_SIZE;
      launch.need += MID_PDU_SIZE;		/* AAL5: need PDU tail */
    }
    dtqneed++;			/* need to work on the end a bit */
  }

  /*
   * finish calculation of launch.need (need to figure out how much padding
   * we will need).   launch.need includes MID_TBD_SIZE, but we need to
   * remove that to so we can round off properly.     we have to add 
   * MID_TBD_SIZE back in after calculating ncells.
   */

  launch.need = roundup(launch.need - MID_TBD_SIZE, MID_ATMDATASZ);
  ncells = launch.need / MID_ATMDATASZ;
  launch.need += MID_TBD_SIZE;

  if (launch.need > EN_TXSZ * 1024) {
    printf("%s: tx%d: packet larger than xmit buffer (%d > %d)\n",
      sc->sc_dev.dv_xname, chan, launch.need, EN_TXSZ * 1024);
    goto dequeue_drop;
  }

  if (launch.need > sc->txslot[chan].bfree) {
    EN_COUNT(sc->txoutspace);
#ifdef EN_DEBUG
    printf("%s: tx%d: out of trasmit space\n", sc->sc_dev.dv_xname, chan);
#endif
    return;		/* >>> exit here if out of obmem buffer space <<< */
  }
  
  /*
   * ensure we have enough dtqs to go, if not, wait for more
   * note that we only need 1 dtq if we are copying everything.
   *
   * XXX: we may want to modify the above to set launch.nodma if launch.mlen is
   * less than a certain size (and avoid the DMA setup costs for small data)
   */

#if 0
  if (launch.mlen < SomeValueToBeDetermined)
    launch.nodma = 1;
#endif

  if (EN_NOTXDMA || !en_dma || launch.nodma) {
    dtqneed = 1;
    launch.nodma = 1;
  }
  if (dtqneed > sc->dtq_free) {
    sc->need_dtqs = 1;
    EN_COUNT(sc->txdtqout);
#ifdef EN_DEBUG
    printf("%s: tx%d: out of trasmit DTQs\n", sc->sc_dev.dv_xname, chan);
#endif
    return;		/* >>> exit here if out of dtqs <<< */
  }

  /*
   * it is a go, commit!  dequeue mbuf start working on the xfer.
   */

  IF_DEQUEUE(&sc->txslot[chan].q, tmp);
#ifdef EN_DIAG
  if (launch.t != tmp)
    panic("en dequeue");
#endif /* EN_DIAG */

  /*
   * launch!
   */

  EN_COUNT(sc->launch);
  if ((launch.atm_flags & EN_OBHDR) == 0) {
    EN_COUNT(sc->lheader);
    /* store tbd1/tbd2 in network byte order */
    launch.tbd1 = htonl(MID_TBD_MK1(launch.aal, sc->txspeed[launch.atm_vci], 
		ncells));
    launch.tbd2 = htonl(MID_TBD_MK2(launch.atm_vci, 0, 0));
  }
  if ((launch.atm_flags & EN_OBTRL) == 0 && launch.aal == MID_TBD_AAL5) {
    EN_COUNT(sc->ltail);
    /* store pdu1 in network byte order */
    launch.pdu1 = htonl(MID_PDU_MK1(0, 0, datalen));
  }

  en_txlaunch(sc, chan, &launch);
  
  /*
   * do some housekeeping and get the next packet
   */

  sc->txslot[chan].bfree -= launch.need;
  IF_ENQUEUE(&sc->txslot[chan].indma, launch.t);
  goto again;

  /*
   * END of txdma loop!
   */

  /*
   * error handles
   */

dequeue_drop:
  IF_DEQUEUE(&sc->txslot[chan].q, tmp);
  if (launch.t != tmp)
    panic("en dequeue drop");
  m_freem(launch.t);
  sc->txslot[chan].mbsize -= launch.mlen;
  goto again;
}


/*
 * en_txlaunch: launch an mbuf into the dma pool!   note that we have
 * en_mfix()ed any strange mbufs so we can count on u_int32_t alignment.
 */

STATIC void en_txlaunch(sc, chan, l)

struct en_softc *sc;
int chan;
struct en_launch *l;

{
  struct mbuf *tmp;
  u_int32_t cur = sc->txslot[chan].cur,
	    start = sc->txslot[chan].start,
	    stop = sc->txslot[chan].stop,
	    dma, *data, *datastop, count, bcode;
  int pad, addtail, need, last, len, needalign, cnt;


 /*
  * vars:
  *   need = # bytes card still needs (decr. to zero)
  *   len = # of bytes left in current mbuf
  *   cur = our current pointer
  *   dma = last place we programmed into the DMA
  *   data = pointer into data area of mbuf that needs to go next
  *   cnt = # of bytes to transfer in this DTQ
  *   bcode/count = DMA burst code, and chip's version of cnt
  *
  * note that for odd length mbufs we have already padded them out with 
  * zeros, so "len" and "need" are rounded up to a word boundary.    an 
  * odd length mbuf can only happen on the last mbuf of a chain [because we've 
  * done en_mfix on the chain].    for aal5, the true length is already in
  * l->pdu.
  */

 need = roundup(l->need, sizeof(u_int32_t));
 dma = cur;
 addtail = (l->atm_flags & EN_OBTRL) == 0;	/* add a tail? */

#ifdef EN_DIAG
  if ((need - MID_TBD_SIZE) % MID_ATMDATASZ) 
    printf("%s: tx%d: bogus trasmit needs (%d)\n", sc->sc_dev.dv_xname, chan,
		need);
#endif
#ifdef EN_DEBUG
  printf("%s: tx%d: launch mbuf 0x%x!   cur=0x%x[%d], need=%d, addtail=%d\n",
	sc->sc_dev.dv_xname, chan, l->t, cur, (cur-start)/4, need, addtail);
  count = EN_READ(sc, MIDX_PLACE(chan));
  printf("     HW: base_address=0x%x, size=%d, read=%d, descstart=%d\n",
	MIDX_BASE(count), MIDX_SZ(count), EN_READ(sc, MIDX_READPTR(chan)), 
	EN_READ(sc, MIDX_DESCSTART(chan)));
#endif

 /*
  * do we need to insert the TBD by hand?
  */

  if ((l->atm_flags & EN_OBHDR) == 0) {
    /* note: data already in correct byte order.  use WRITEDAT to xfer */
#ifdef EN_DEBUG
    printf("%s: tx%d: insert header 0x%x 0x%x\n", sc->sc_dev.dv_xname,
	chan, ntohl(l->tbd1), ntohl(l->tbd2));
#endif
    EN_WRITEDAT(sc, cur, l->tbd1);
    EN_WRAPADD(start, stop, cur, 4);
    EN_WRITEDAT(sc, cur, l->tbd2);
    EN_WRAPADD(start, stop, cur, 4);
    need -= 8;
  }

  /*
   * now do the mbufs...
   */

  last = 0;
  for (tmp = l->t ; tmp != NULL ; tmp = tmp->m_next) {

    /* get pointer to data and length */
    data = mtod(tmp, u_int32_t *);
    len = roundup(tmp->m_len, sizeof(u_int32_t));
    last = (tmp->m_next == NULL);
    if (tmp == l->t) {
      data += sizeof(struct atm_pseudohdr)/sizeof(u_int32_t);
      len -= sizeof(struct atm_pseudohdr);
    }

    /* now, determine if we should copy it */
    if (l->nodma || len < EN_MINDMA) {
      datastop = data + (len / sizeof(u_int32_t));
      /* copy loop: preserve byte order!!!  use WRITEDAT */
      while (data != datastop) {
	EN_WRITEDAT(sc, cur, *data);
	data++;
	EN_WRAPADD(start, stop, cur, 4);
      }
      need -= len;
#ifdef EN_DEBUG
      printf("%s: tx%d: copied %d bytes (%d left, cur now 0x%x)\n", 
		sc->sc_dev.dv_xname, chan, len, need, cur);
#endif
      continue;		/* continue on to next mbuf */
    }

    /* going to do DMA, first make sure the dtq is in sync. */
    if (dma != cur) {
      EN_DTQADD(sc, WORD_IDX(start,cur), chan, MIDDMA_JK, 0);
#ifdef EN_DEBUG
      printf("%s: tx%d: dtq_sync: advance pointer to %d\n",
		sc->sc_dev.dv_xname, chan, cur);
#endif
    }

    /* do we need to do a DMA op to align? */
    if (sc->alburst && 
	(needalign = (((u_int) data) & sc->bestburstmask)) != 0) {
      cnt = sc->bestburstlen - needalign;
      count = cnt / sizeof(u_int32_t);
      bcode = en_dmaplan[count].bcode;
      count = cnt >> en_dmaplan[count].divshift;
      need -= cnt;
      EN_WRAPADD(start, stop, cur, cnt);
#ifdef EN_DEBUG
      printf("%s: tx%d: al_dma %d bytes (%d left, cur now 0x%x)\n", 
		sc->sc_dev.dv_xname, chan, cnt, need, cur);
#endif
      len -= cnt;
      if (len == 0 && last && addtail == 0) {
	EN_DTQADDEND(sc, count, chan, bcode, vtophys(data), l->mlen);
	goto done;		/* finished ! */
      }
      EN_DTQADD(sc, count, chan, bcode, vtophys(data));
      data = (u_int32_t *) ((u_char *)data + cnt);
    }

    /* do we need to do a max-sized burst? */
    if (len >= sc->bestburstlen) {
      count = len >> sc->bestburstshift;
      cnt = count << sc->bestburstshift;
      bcode = sc->bestburstcode;
      need -= cnt;
      EN_WRAPADD(start, stop, cur, cnt);
#ifdef EN_DEBUG
      printf("%s: tx%d: best_dma %d bytes (%d left, cur now 0x%x)\n", 
		sc->sc_dev.dv_xname, chan, cnt, need, cur);
#endif
      len -= cnt;
      if (len == 0 && last && addtail == 0) {
	EN_DTQADDEND(sc, count, chan, bcode, vtophys(data), l->mlen);
	goto done;		/* finished ! */
      }
      EN_DTQADD(sc, count, chan, bcode, vtophys(data));
      data = (u_int32_t *) ((u_char *)data + cnt);
    }

    /* do we need to do a cleanup burst? */
    if (len) {
      count = len / sizeof(u_int32_t);
      bcode = en_dmaplan[count].bcode;
      count = len >> en_dmaplan[count].divshift;
      need -= len;
      EN_WRAPADD(start, stop, cur, len);
#ifdef EN_DEBUG
      printf("%s: tx%d: cleanup_dma %d bytes (%d left, cur now 0x%x)\n", 
		sc->sc_dev.dv_xname, chan, len, need, cur);
#endif
      if (last && addtail == 0) {
	EN_DTQADDEND(sc, count, chan, bcode, vtophys(data), l->mlen);
	goto done;		/* finished ! */
      }
      EN_DTQADD(sc, count, chan, bcode, vtophys(data));
    }

    dma = cur;		/* update dma pointer */

  } /* next mbuf, please */

  /*
   * all mbuf data has been copied out to the obmem (or set up to be DMAd).
   * if the trailer or padding needs to be put in, do it now.  note that
   * we round down the padding size since we may have already padded some.
   */

  if (addtail) {

    /* copy data */
    pad = need / sizeof(u_int32_t);	/* round *down* */
    if (l->aal == MID_TBD_AAL5)
      pad -= 2;
#ifdef EN_DEBUG
      printf("%s: tx%d: padding %d bytes\n", 
		sc->sc_dev.dv_xname, chan, pad * sizeof(u_int32_t));
#endif
    while (pad--) {
      EN_WRITEDAT(sc, cur, 0);	/* no byte order issues with zero */
      EN_WRAPADD(start, stop, cur, 4);
    }
    if (l->aal == MID_TBD_AAL5) {
      EN_WRITEDAT(sc, cur, l->pdu1); /* already in network order */
      EN_WRAPADD(start, stop, cur, 8);
    }
  }

  if (addtail || dma != cur) {
   /* write final descritor  */
    EN_DTQADDEND(sc, WORD_IDX(start,cur), chan, MIDDMA_JK, 0, l->mlen);
    /* dma = cur; */ 	/* not necessary since we are done */
  }

done:
  /* update current pointer */
  sc->txslot[chan].cur = cur;
#ifdef EN_DEBUG
      printf("%s: tx%d: DONE!   cur now = 0x%x\n", 
		sc->sc_dev.dv_xname, chan, cur);
#endif

  return;
}


/*
 * interrupt handler
 */

int en_intr(arg)

void *arg;

{
  struct en_softc *sc = (struct en_softc *) arg;
  struct mbuf *m;
  struct atm_pseudohdr ah;
  u_int32_t reg, kick, val, mask, chip, vci, slot, dtq, drq;
  int lcv, idx, need_softserv = 0;

  reg = EN_READ(sc, MID_INTACK);

  if ((reg & MID_INT_ANY) == 0) 
    return(0); /* not us */

#ifdef EN_DEBUG
  printf("%s: interrupt=0x%b\n", sc->sc_dev.dv_xname, reg, MID_INTBITS);
#endif

  /*
   * unexpected errors that need a reset
   */

  if ((reg & (MID_INT_IDENT|MID_INT_LERR|MID_INT_DMA_ERR|MID_INT_SUNI)) != 0) {
    printf("%s: unexpected interrupt=0x%b, resetting card\n", 
	sc->sc_dev.dv_xname, reg, MID_INTBITS);
#ifdef EN_DEBUG
#ifdef DDB
    Debugger();
#endif	/* DDB */
    sc->enif.if_flags &= ~IFF_RUNNING; /* FREEZE! */
#else
    en_reset(sc);
    en_init(sc);
#endif
    return(1);
  }

  /*******************
   * xmit interrupts *
   ******************/

  kick = 0;				/* bitmask of channels to kick */
  if (reg & MID_INT_TX) {		/* TX done! */

    /*
     * check for tx complete, if detected then this means that some space
     * has come free on the card.   we must account for it and arrange to
     * kick the channel to life (in case it is stalled waiting on the card).
     */
    for (mask = 1, lcv = 0 ; lcv < EN_NTX ; lcv++, mask = mask * 2) {
      if (reg & MID_TXCHAN(lcv)) {
	kick = kick | mask;	/* want to kick later */
	val = EN_READ(sc, MIDX_READPTR(lcv));	/* current read pointer */
	val = (val * sizeof(u_int32_t)) + sc->txslot[lcv].start;
						/* convert to offset */
	if (val > sc->txslot[lcv].cur)
	  sc->txslot[lcv].bfree = val - sc->txslot[lcv].cur;
	else
	  sc->txslot[lcv].bfree = (val + (EN_TXSZ*1024)) - sc->txslot[lcv].cur;
#ifdef EN_DEBUG
	printf("%s: tx%d: trasmit done.   %d bytes now free in buffer\n",
		sc->sc_dev.dv_xname, lcv, sc->txslot[lcv].bfree);
#endif
      }
    }
  }

  if (reg & MID_INT_DMA_TX) {		/* TX DMA done! */

  /*
   * check for TX DMA complete, if detected then this means that some DTQs
   * are now free.   it also means some indma mbufs can be freed.
   * if we needed DTQs, kick all channels.
   */
    val = EN_READ(sc, MID_DMA_RDTX);	/* chip's current location */
    idx = MID_DTQ_A2REG(sc->dtq_chip);/* where we last saw chip */
    if (sc->need_dtqs) {
      kick = MID_NTX_CH - 1;		/* assume power of 2, kick all! */
      sc->need_dtqs = 0;		/* recalculated in "kick" loop below */
#ifdef EN_DEBUG
      printf("%s: cleared need DTQ condition\n", sc->sc_dev.dv_xname);
#endif
    }
    do {				/* while idx != val */ 
      sc->dtq_free++;
      if ((dtq = sc->dtq[idx]) != 0) {
        sc->dtq[idx] = 0;	/* don't forget to zero it out when done */
	slot = EN_DQ_SLOT(dtq);
	IF_DEQUEUE(&sc->txslot[slot].indma, m);
	if (!m) panic("enintr: dtqsync");
	sc->txslot[slot].mbsize -= EN_DQ_LEN(dtq);
#ifdef EN_DEBUG
	printf("%s: tx%d: free %d dma bytes, mbsize now %d\n",
		sc->sc_dev.dv_xname, slot, EN_DQ_LEN(dtq), 
		sc->txslot[slot].mbsize);
#endif
	m_freem(m);
      }
      EN_WRAPADD(0, MID_DTQ_N, idx, 1);
    } while (idx != val);
    sc->dtq_chip = MID_DTQ_REG2A(val);	/* sync softc */
  }


  /*
   * kick xmit channels as needed
   */

  if (kick) {
#ifdef EN_DEBUG
  printf("%s: tx kick mask = 0x%x\n", sc->sc_dev.dv_xname, kick);
#endif
    for (mask = 1, lcv = 0 ; lcv < EN_NTX ; lcv++, mask = mask * 2) {
      if ((kick & mask) && sc->txslot[lcv].q.ifq_head) {
	en_txdma(sc, lcv);		/* kick it! */
      }
    }		/* for each slot */
  }		/* if kick */


  /*******************
   * recv interrupts *
   ******************/

  /*
   * check for RX DMA complete, and pass the data "upstairs"
   */

  if (reg & MID_INT_DMA_RX) {
    val = EN_READ(sc, MID_DMA_RDRX); /* chip's current location */
    idx = MID_DRQ_A2REG(sc->drq_chip);/* where we last saw chip */
    do {				/* while (idx != val)  */
      sc->drq_free++;
      if ((drq = sc->drq[idx]) != 0) {
        sc->drq[idx] = 0;	/* don't forget to zero it out when done */
	slot = EN_DQ_SLOT(drq);
	IF_DEQUEUE(&sc->rxslot[slot].indma, m);
	if (!m) {
	  printf("%s: lost mbuf in slot %d!\n", sc->sc_dev.dv_xname, slot);
	  panic("enintr: drqsync");
	}

	/* do something with this mbuf */
	if (sc->rxslot[slot].oth_flags & ENOTHER_DRAIN) {  /* drain? */
	  m_freem(m);
	  vci = sc->rxslot[slot].atm_vci;
	  if (sc->rxslot[slot].indma.ifq_head == NULL &&
		sc->rxslot[slot].q.ifq_head == NULL &&
		(EN_READ(sc, MID_VC(vci)) & MIDV_INSERVICE) == 0 &&
		(sc->rxslot[slot].oth_flags & ENOTHER_SWSL) == 0) {
	    sc->rxslot[slot].oth_flags = ENOTHER_FREE; /* done drain */
	    sc->rxslot[slot].atm_vci = RX_NONE;
	    sc->rxvc2slot[vci] = RX_NONE;
#ifdef EN_DEBUG
	    printf("%s: rx%d: VCI %d now free\n", sc->sc_dev.dv_xname,
			slot, vci);
#endif
	  }
	} else {
	  ATM_PH_FLAGS(&ah) = sc->rxslot[slot].atm_flags;
	  ATM_PH_VPI(&ah) = 0;
	  ATM_PH_SETVCI(&ah, sc->rxslot[slot].atm_vci);
#ifdef EN_DEBUG
	  printf("%s: rx%d: rxvci%d: atm_input, mbuf 0x%x, len %d, hand 0x%x\n",
		sc->sc_dev.dv_xname, slot, sc->rxslot[slot].atm_vci, m,
		EN_DQ_LEN(drq), sc->rxslot[slot].rxhand);
#endif
	  atm_input(&sc->enif, &ah, m, sc->rxslot[slot].rxhand);
	}

      }
      EN_WRAPADD(0, MID_DRQ_N, idx, 1);
    } while (idx != val);
    sc->drq_chip = MID_DRQ_REG2A(val);	/* sync softc */

    if (sc->need_drqs) {	/* true if we had a DRQ shortage */
      need_softserv = 1;
      sc->need_drqs = 0;
#ifdef EN_DEBUG
	printf("%s: cleared need DRQ condition\n", sc->sc_dev.dv_xname);
#endif
    }
  }

  /*
   * handle service interrupts
   */

  if (reg & MID_INT_SERVICE) {
    chip = MID_SL_REG2A(EN_READ(sc, MID_SERV_WRITE));

    do {				/* while sc->hwslistp != chip */

      /* fetch and remove it from hardware service list */
      vci = EN_READ(sc, sc->hwslistp);
      slot = sc->rxvc2slot[vci];
      if (slot == RX_NONE) {
	printf("%s: unexpected rx interrupt on VCI %d\n", sc->sc_dev.dv_xname, 
	    EN_READ(sc, sc->hwslistp));
	panic("enintr: service");
      }
      EN_WRITE(sc, MID_VC(vci), sc->rxslot[slot].mode); /* remove from hwsl */
      EN_WRAPADD(MID_SLOFF, MID_SLEND, sc->hwslistp, 4);/* advance hw ptr */
      EN_COUNT(sc->hwpull);

#ifdef EN_DEBUG
      printf("%s: pulled VCI %d off hwslist\n", sc->sc_dev.dv_xname, vci);
#endif

      /* add it to the software service list (if needed) */
      if ((sc->rxslot[slot].oth_flags & ENOTHER_SWSL) == 0) {
	EN_COUNT(sc->swadd);
	need_softserv = 1;
	sc->rxslot[slot].oth_flags |= ENOTHER_SWSL;
	sc->swslist[sc->swsl_tail] = slot;
	EN_WRAPADD(0, MID_SL_N, sc->swsl_tail, 1);
	sc->swsl_size++;
#ifdef EN_DEBUG
      printf("%s: added VCI %d to swslist\n", sc->sc_dev.dv_xname, vci);
#endif
      }
    } while (sc->hwslistp != chip);   
  }

  /*
   * now service (function too big to include here)
   */

  if (need_softserv)
    en_service(sc);

  /*
   * keep our stats
   */

  if (reg & MID_INT_DMA_OVR) {
    EN_COUNT(sc->dmaovr);
#ifdef EN_DEBUG
    printf("%s: MID_INT_DMA_OVR\n", sc->sc_dev.dv_xname);
#endif
  }
  reg = EN_READ(sc, MID_STAT);
#ifdef EN_STAT
  sc->otrash += MID_OTRASH(reg);
  sc->vtrash += MID_VTRASH(reg);
#endif

  return(1);
}


/*
 * en_service: handle a service interrupt
 *
 * Q: why do we need a software service list?
 *
 * A: if we remove a VCI from the hardware list and we find that we are
 *    out of DRQs we must defer processing until some DRQs become free.
 *    so we must remember to look at this RX VCI/slot later, but we can't
 *    put it back on the hardware service list (since that isn't allowed).
 *    so we instead save it on the software service list.   it would be nice 
 *    if we could peek at the VCI on top of the hwservice list without removing
 *    it, however this leads to a race condition: if we peek at it and
 *    decide we are done with it new data could come in before we have a 
 *    chance to remove it from the hwslist.   by the time we get it out of
 *    the list the interrupt for the new data will be lost.   oops!
 *
 */

STATIC void en_service(sc)

struct en_softc *sc;

{
  struct mbuf *m, *tmp;
  u_int32_t cur, dstart, rbd, pdu, *sav, dma, bcode, count, *data, *datastop;
  u_int32_t start, stop, cnt, needalign;
  int slot, raw, aal5, llc, vci, fill, mlen, tlen, drqneed, need, needfill;

next_vci:
  if (sc->swsl_size == 0) {
#ifdef EN_DEBUG
    printf("%s: en_service done\n", sc->sc_dev.dv_xname);
#endif
    return;		/* >>> exit here if swsl now empty <<< */
  }

  /*
   * get slot/vci to service
   */

  slot = sc->swslist[sc->swsl_head];
  vci = sc->rxslot[slot].atm_vci;
#ifdef EN_DIAG
  if (sc->rxvc2slot[vci] != slot) panic("en_service rx slot/vci sync");
#endif

  /*
   * determine our mode and if we've got any work to do
   */

  raw = sc->rxslot[slot].oth_flags & ENOTHER_RAW;
  start= sc->rxslot[slot].start;
  stop= sc->rxslot[slot].stop;
  cur = sc->rxslot[slot].cur;

#ifdef EN_DEBUG
  printf("%s: rx%d: service vci=%d raw=%d start/stop/cur=0x%x 0x%x 0x%x\n",
	sc->sc_dev.dv_xname, slot, vci, raw, start, stop, cur);
#endif

same_vci:
  dstart = MIDV_DSTART(EN_READ(sc, MID_DST_RP(vci)));
  dstart = (dstart * sizeof(u_int32_t)) + start;

  /* check to see if there is any data at all */
  if (dstart == cur) {
    EN_WRAPADD(0, MID_SL_N, sc->swsl_head, 1); 
    sc->rxslot[slot].oth_flags &= ~ENOTHER_SWSL;
    sc->swsl_size--;
					/* >>> remove from swslist <<< */
#ifdef EN_DEBUG
    printf("%s: rx%d: remove vci %d from swslist\n", 
		sc->sc_dev.dv_xname, slot, vci);
#endif
    goto next_vci;
  }

  /*
   * figure out how many bytes we need
   * [mlen = # bytes to go in mbufs, fill = # bytes to dump (MIDDMA_JK)]
   */

  if (raw) {

    /* raw mode (aka boodi mode) */
    fill = 0;
    if (dstart > cur)
      mlen = dstart - cur;
    else
      mlen = (dstart + (EN_RXSZ*1024)) - cur;

  } else {

    /* normal mode */
    aal5 = (sc->rxslot[slot].atm_flags & ATM_PH_AAL5);
    llc = (aal5 && (sc->rxslot[slot].atm_flags & ATM_PH_LLCSNAP)) ? 1 : 0;
    rbd = EN_READ(sc, cur);
    if (MID_RBD_ID(rbd) != MID_RBD_STDID) 
      panic("en_service: id mismatch\n");

    if (rbd & MID_RBD_T) {
      mlen = 0;			/* we've got trash */
      fill = MID_RBD_SIZE;
      EN_COUNT(sc->ttrash);
    } else if (!aal5) {
      mlen = MID_RBD_SIZE + MID_CHDR_SIZE + MID_ATMDATASZ; /* 1 cell (ick!) */
      fill = 0;
    } else {
      tlen = (MID_RBD_CNT(rbd) * MID_ATMDATASZ) + MID_RBD_SIZE;
      pdu = cur + tlen - MID_PDU_SIZE;
      if (pdu >= stop)
	pdu -= (EN_RXSZ*1024);
      pdu = EN_READ(sc, pdu);		/* READ swaps to proper byte order */
      fill = tlen - MID_RBD_SIZE - MID_PDU_LEN(pdu);
      mlen = tlen - fill;
    }

  }

  /*
   * now allocate mbufs for mlen bytes of data, if out of mbufs, trash all
   *
   * notes:
   *  1. it is possible that we've already allocated an mbuf for this pkt
   *	 but ran out of DRQs, in which case we saved the allocated mbuf on
   *	 "q".
   *  2. if we save an mbuf in "q" we store the "cur" (pointer) in the front 
   *     of the mbuf as an identity (that we can check later), and we also
   *     store drqneed (so we don't have to recompute it).
   *  3. after this block of code, if m is still NULL then we ran out of mbufs
   */
  
  m = sc->rxslot[slot].q.ifq_head;
  if (m) {
    sav = mtod(m, u_int32_t *);
    if (sav[0] != cur) {
#ifdef EN_DEBUG
      printf("%s: rx%d: q'ed mbuf 0x%x not ours\n", 
		sc->sc_dev.dv_xname, slot, m);
#endif
      m = NULL;			/* wasn't ours */
      EN_COUNT(sc->rxqnotus);
    } else {
      EN_COUNT(sc->rxqus);
      IF_DEQUEUE(&sc->rxslot[slot].q, m);
      drqneed = sav[1];
#ifdef EN_DEBUG
      printf("%s: rx%d: recovered q'ed mbuf 0x%x (drqneed=%d)\n", 
	sc->sc_dev.dv_xname, slot, drqneed);
#endif
    }
  }

  if (m == NULL) {
    m = en_mget(sc, mlen, &drqneed);		/* allocate! */
    if (m == NULL) {
      fill += mlen;
      mlen = 0;
      EN_COUNT(sc->rxmbufout);
#ifdef EN_DEBUG
      printf("%s: rx%d: out of mbufs\n", sc->sc_dev.dv_xname, slot);
#endif
    }
#ifdef EN_DEBUG
    printf("%s: rx%d: allocate mbuf 0x%x, mlen=%d, drqneed=%d\n", 
	sc->sc_dev.dv_xname, slot, m, mlen, drqneed);
#endif
  }

#ifdef EN_DEBUG
  printf("%s: rx%d: VCI %d, mbuf_chain 0x%x, mlen %d, fill %d\n",
	sc->sc_dev.dv_xname, slot, vci, m, mlen, fill);
#endif

  /*
   * now check to see if we've got the DRQs needed.    if we are out of 
   * DRQs we must quit (saving our mbuf, if we've got one).
   */

  needfill = (fill) ? 1 : 0;
  if (drqneed + needfill > sc->drq_free) {
    sc->need_drqs = 1;	/* flag condition */
    if (m == NULL) {
      EN_COUNT(sc->rxoutboth);
#ifdef EN_DEBUG
      printf("%s: rx%d: out of DRQs *and* mbufs!\n", sc->sc_dev.dv_xname, slot);
#endif
      return;		/* >>> exit here if out of both mbufs and DRQs <<< */
    }
    sav = mtod(m, u_int32_t *);
    sav[0] = cur;
    sav[1] = drqneed;
    IF_ENQUEUE(&sc->rxslot[slot].q, m);
    EN_COUNT(sc->rxdrqout);
#ifdef EN_DEBUG
    printf("%s: rx%d: out of DRQs\n", sc->sc_dev.dv_xname, slot);
#endif
    return;		/* >>> exit here if out of DRQs <<< */
  }

  /*
   * at this point all resources have been allocated and we are commited 
   * to servicing this slot.
   *
   * dma = last location we told chip about
   * cur = current location
   * mlen = space in the mbuf we want
   * need = bytes to xfer in (decrs to zero)
   * fill = how much fill we need
   * tlen = how much data to transfer to this mbuf
   * cnt/bcode/count = <same as xmit>
   *
   * 'needfill' not used after this point
   */

  dma = cur;		/* dma = last location we told chip about */
  need = roundup(mlen, sizeof(u_int32_t));
  fill = fill - (need - mlen);  /* note: may invalidate 'needfill' */

  for (tmp = m ; tmp != NULL && need > 0 ; tmp = tmp->m_next) {
    tlen = roundup(tmp->m_len, sizeof(u_int32_t)); /* m_len set by en_mget */
    data = mtod(tmp, u_int32_t *);

#ifdef EN_DEBUG
    printf("%s: rx%d: load mbuf 0x%x, m_len=%d, m_data=0x%x, tlen=%d\n",
	sc->sc_dev.dv_xname, slot, tmp, tmp->m_len, tmp->m_data, tlen);
#endif
    
    /* copy data */
    if (EN_NORXDMA || !en_dma || tlen < EN_MINDMA) {
      datastop = (u_int32_t *)((u_char *) data + tlen);
      /* copy loop: preserve byte order!!!  use READDAT */
      while (data != datastop) {
	*data = EN_READDAT(sc, cur);
	data++;
	EN_WRAPADD(start, stop, cur, 4);
      }
      need -= tlen;
#ifdef EN_DEBUG
      printf("%s: rx%d: vci%d: copied %d bytes (%d left)\n",
		sc->sc_dev.dv_xname, slot, vci, tlen, need);
#endif
      continue;
    }

    /* DMA data (check to see if we need to sync DRQ first) */
    if (dma != cur) {
      EN_DRQADD(sc, WORD_IDX(start,cur), vci, MIDDMA_JK, 0);
#ifdef EN_DEBUG
      printf("%s: rx%d: vci%d: drq_sync: advance pointer to %d\n",
		sc->sc_dev.dv_xname, slot, vci, cur);
#endif
    }

    /* do we need to do a DMA op to align? */
    if (sc->alburst &&
      (needalign = (((u_int) data) & sc->bestburstmask)) != 0) {
      cnt = sc->bestburstlen - needalign;
      count = cnt / sizeof(u_int32_t);
      bcode = en_dmaplan[count].bcode;
      count = cnt >> en_dmaplan[count].divshift;
      need -= cnt;
      EN_WRAPADD(start, stop, cur, cnt);
#ifdef EN_DEBUG
      printf("%s: rx%d: vci%d: al_dma %d bytes (%d left)\n",
		sc->sc_dev.dv_xname, slot, vci, cnt, need);
#endif
      tlen -= cnt;
      if (need == 0 && !fill) {
	EN_DRQADDEND(sc, count, vci, bcode, vtophys(data), mlen, slot);
	goto done;		/* finished! */
      }
      EN_DRQADD(sc, count, vci, bcode, vtophys(data));
      data = (u_int32_t *)((u_char *) data + cnt);   
    }

    /* do we need a max-sized burst? */
    if (tlen >= sc->bestburstlen) {
      count = tlen >> sc->bestburstshift;
      cnt = count << sc->bestburstshift;
      bcode = sc->bestburstcode;
      need -= cnt;
      EN_WRAPADD(start, stop, cur, cnt);
#ifdef EN_DEBUG
      printf("%s: rx%d: vci%d: best_dma %d bytes (%d left)\n",
		sc->sc_dev.dv_xname, slot, vci, cnt, need);
#endif
      tlen -= cnt;
      if (need == 0 && !fill) {
	EN_DRQADDEND(sc, count, vci, bcode, vtophys(data), mlen, slot);
	goto done;		/* finished! */
      }
      EN_DRQADD(sc, count, vci, bcode, vtophys(data));
      data = (u_int32_t *)((u_char *) data + cnt);   
    }

    /* do we need to do a cleanup burst? */
    if (tlen) {
      count = tlen / sizeof(u_int32_t);
      bcode = en_dmaplan[count].bcode;
      count = tlen >> en_dmaplan[count].divshift;
      need -= tlen;
      EN_WRAPADD(start, stop, cur, tlen);
#ifdef EN_DEBUG
      printf("%s: rx%d: vci%d: cleanup_dma %d bytes (%d left)\n",
		sc->sc_dev.dv_xname, slot, vci, tlen, need);
#endif
      if (need == 0 && !fill) {
	EN_DRQADDEND(sc, count, vci, bcode, vtophys(data), mlen, slot);
	goto done;		/* finished! */
      }
      EN_DRQADD(sc, count, vci, bcode, vtophys(data));
    }

    dma = cur;		/* update dma pointer */

  }

  /* skip the end */
  if (fill || dma != cur) {
#ifdef EN_DEBUG
      if (fill)
        printf("%s: rx%d: vci%d: skipping %d bytes of fill\n",
		sc->sc_dev.dv_xname, slot, vci, fill);
      else
        printf("%s: rx%d: vci%d: syncing chip from 0x%x to 0x%x [cur]\n",
		sc->sc_dev.dv_xname, slot, vci, dma, cur);
#endif
    EN_WRAPADD(start, stop, cur, fill);
    EN_DRQADDEND(sc, WORD_IDX(start,cur), vci, MIDDMA_JK, 0, mlen, slot);
    /* dma = cur; */	/* not necessary since we are done */
  }

  /*
   * done, remove stuff we don't want to pass up:
   *   raw mode (boodi mode): pass everything up for later processing
   *   aal5: remove RBD
   *   aal0: remove RBD + cell header
   */

done:
  if (m) {
    if (!raw) {
      cnt = MID_RBD_SIZE;
      if (!aal5) cnt += MID_CHDR_SIZE;
      m->m_len -= cnt;				/* chop! */
      m->m_pkthdr.len -= cnt;
      m->m_data += cnt;
    }
    IF_ENQUEUE(&sc->rxslot[slot].indma, m);
  }
  sc->rxslot[slot].cur = cur;		/* update master copy of 'cur' */

#ifdef EN_DEBUG
  printf("%s: rx%d: vci%d: DONE!   cur now =0x%x\n", 
	sc->sc_dev.dv_xname, slot, vci, cur);
#endif

  goto same_vci;	/* get next packet in this slot */
}


#ifdef EN_DDBHOOK
/*
 * functions we can call from ddb
 */

/*
 * en_dump: dump the state
 */

#define END_SWSL	0x00000040		/* swsl state */
#define END_DRQ		0x00000020		/* drq state */
#define END_DTQ		0x00000010		/* dtq state */
#define END_RX		0x00000008		/* rx state */
#define END_TX		0x00000004		/* tx state */
#define END_MREGS	0x00000002		/* registers */
#define END_STATS	0x00000001		/* dump stats */

#define END_BITS "\20\7SWSL\6DRQ\5DTQ\4RX\3TX\2MREGS\1STATS"

int en_dump(unit, level)

int unit, level;

{
  struct en_softc *sc;
  int lcv, cnt, slot;
  u_int32_t ptr, reg;

  for (lcv = 0 ; lcv < en_cd.cd_ndevs ; lcv++) {
    sc = (struct en_softc *) en_cd.cd_devs[lcv];
    if (sc == NULL) continue;
    if (unit != -1 && unit != lcv)
      continue;

    printf("dumping device %s at level 0x%b\n", sc->sc_dev.dv_xname, level,
			END_BITS);

    if (sc->dtq_us == 0) {
      printf("<hasn't been en_init'd yet>\n");
      continue;
    }

    if (level & END_STATS) {
      printf("  en_stats:\n");
      printf("    %d mbufs fixed by mfix (should be zero)\n", sc->mfix);
      printf("    %d rx dma overflow interrupts\n", sc->dmaovr);
      printf("    %d times we ran out of TX space and stalled\n", 
							sc->txoutspace);
      printf("    %d times we ran out of DTQs\n", sc->txdtqout);
      printf("    %d times we launched a packet\n", sc->launch);
      printf("    %d times we launched without on-board header\n", sc->lheader);
      printf("    %d times we launched without on-board tail\n", sc->ltail);
      printf("    %d times we pulled the hw service list\n", sc->hwpull);
      printf("    %d times we pushed a vci on the sw service list\n", 
								sc->swadd);
      printf("    %d times RX pulled an mbuf from Q that wasn't ours\n", 
							 sc->rxqnotus);
      printf("    %d times RX pulled a good mbuf from Q\n", sc->rxqus);
      printf("    %d times we ran out of mbufs *and* DRQs\n", sc->rxoutboth);
      printf("    %d times we ran out of DRQs\n", sc->rxdrqout);

      printf("    %d trasmit packets dropped due to mbsize\n", sc->txmbovr);
      printf("    %d cells trashed due to turned off rxvc\n", sc->vtrash);
      printf("    %d cells trashed due to totally full buffer\n", sc->otrash);
      printf("    %d cells trashed due almost full buffer\n", sc->ttrash);
      printf("    %d rx mbuf allocation failures\n", sc->rxmbufout);
#ifdef NATM
      printf("    %d drops at natmintrq\n", natmintrq.ifq_drops);
#ifdef NATM_STAT
      printf("    natmintr so_rcv: ok/drop cnt: %d/%d, ok/drop bytes: %d/%d\n",
	natm_sookcnt, natm_sodropcnt, natm_sookbytes, natm_sodropbytes);
#endif
#endif
    }

    if (level & END_MREGS) {
      printf("mregs:\n");
      printf("resid = 0x%x\n", EN_READ(sc, MID_RESID));
      printf("interrupt status = 0x%b\n", 
				EN_READ(sc, MID_INTSTAT), MID_INTBITS);
      printf("interrupt enable = 0x%b\n", 
				EN_READ(sc, MID_INTENA), MID_INTBITS);
      printf("mcsr = 0x%b\n", EN_READ(sc, MID_MAST_CSR), MID_MCSRBITS);
      printf("serv_write = [chip=%d] [us=%d]\n", EN_READ(sc, MID_SERV_WRITE),
			MID_SL_A2REG(sc->hwslistp));
      printf("dma addr = 0x%x\n", EN_READ(sc, MID_DMA_ADDR));
      printf("DRQ: chip[rd=0x%x,wr=0x%x], sc[chip=0x%x,us=0x%x]\n",
	MID_DRQ_REG2A(EN_READ(sc, MID_DMA_RDRX)), 
	MID_DRQ_REG2A(EN_READ(sc, MID_DMA_WRRX)), sc->drq_chip, sc->drq_us);
      printf("DTQ: chip[rd=0x%x,wr=0x%x], sc[chip=0x%x,us=0x%x]\n",
	MID_DTQ_REG2A(EN_READ(sc, MID_DMA_RDTX)), 
	MID_DTQ_REG2A(EN_READ(sc, MID_DMA_WRTX)), sc->dtq_chip, sc->dtq_us);

      printf("  unusal txspeeds: ");
      for (cnt = 0 ; cnt < MID_N_VC ; cnt++)
	if (sc->txspeed[cnt])
	  printf(" vci%d=0x%x", cnt, sc->txspeed[cnt]);
      printf("\n");

      printf("  rxvc slot mappings: ");
      for (cnt = 0 ; cnt < MID_N_VC ; cnt++)
	if (sc->rxvc2slot[cnt] != RX_NONE)
	  printf("  %d->%d", cnt, sc->rxvc2slot[cnt]);
      printf("\n");

    }

    if (level & END_TX) {
      printf("tx:\n");
      for (slot = 0 ; slot < EN_NTX; slot++) {
	printf("tx%d: start/stop/cur=0x%x/0x%x/0x%x [%d]  ", slot,
	  sc->txslot[slot].start, sc->txslot[slot].stop, sc->txslot[slot].cur,
		(sc->txslot[slot].cur - sc->txslot[slot].start)/4);
	printf("mbsize=%d, bfree=%d\n", sc->txslot[slot].mbsize,
		sc->txslot[slot].bfree);
        printf("txhw: base_address=0x%x, size=%d, read=%d, descstart=%d\n",
	  MIDX_BASE(EN_READ(sc, MIDX_PLACE(slot))), 
	  MIDX_SZ(EN_READ(sc, MIDX_PLACE(slot))),
	  EN_READ(sc, MIDX_READPTR(slot)), EN_READ(sc, MIDX_DESCSTART(slot)));
      }
    }

    if (level & END_RX) {
      printf("  recv slots:\n");
      for (slot = 0 ; slot < sc->en_nrx; slot++) {
	printf("rx%d: vci=%d: start/stop/cur=0x%x/0x%x/0x%x ", slot,
	  sc->rxslot[slot].atm_vci, sc->rxslot[slot].start, 
	  sc->rxslot[slot].stop, sc->rxslot[slot].cur);
	printf("mode=0x%x, atm_flags=0x%x, oth_flags=0x%x\n", 
	sc->rxslot[slot].mode, sc->rxslot[slot].atm_flags, 
		sc->rxslot[slot].oth_flags);
        printf("RXHW: mode=0x%x, DST_RP=0x%x, WP_ST_CNT=0x%x\n",
	  EN_READ(sc, MID_VC(sc->rxslot[slot].atm_vci)),
	  EN_READ(sc, MID_DST_RP(sc->rxslot[slot].atm_vci)),
	  EN_READ(sc, MID_WP_ST_CNT(sc->rxslot[slot].atm_vci)));
      }
    }

    if (level & END_DTQ) {
      printf("  dtq [need_dtqs=%d,dtq_free=%d]:\n", 
					sc->need_dtqs, sc->dtq_free);
      ptr = sc->dtq_chip;
      while (ptr != sc->dtq_us) {
        reg = EN_READ(sc, ptr);
        printf("\t0x%x=[cnt=%d, chan=%d, end=%d, type=%d @ 0x%x]\n", 
	    sc->dtq[MID_DTQ_A2REG(ptr)], MID_DMA_CNT(reg), MID_DMA_TXCHAN(reg),
	    (reg & MID_DMA_END) != 0, MID_DMA_TYPE(reg), EN_READ(sc, ptr+4));
        EN_WRAPADD(MID_DTQOFF, MID_DTQEND, ptr, 8);
      }
    }

    if (level & END_DRQ) {
      printf("  drq [need_drqs=%d,drq_free=%d]:\n", 
					sc->need_drqs, sc->drq_free);
      ptr = sc->drq_chip;
      while (ptr != sc->drq_us) {
        reg = EN_READ(sc, ptr);
	printf("\t0x%x=[cnt=%d, chan=%d, end=%d, type=%d @ 0x%x]\n", 
	  sc->drq[MID_DRQ_A2REG(ptr)], MID_DMA_CNT(reg), MID_DMA_RXVCI(reg),
	  (reg & MID_DMA_END) != 0, MID_DMA_TYPE(reg), EN_READ(sc, ptr+4));
	EN_WRAPADD(MID_DRQOFF, MID_DRQEND, ptr, 8);
      }
    }

    if (level & END_SWSL) {
      printf(" swslist [size=%d]: ", sc->swsl_size);
      for (cnt = sc->swsl_head ; cnt != sc->swsl_tail ; 
			cnt = (cnt + 1) % MID_SL_N)
        printf("0x%x ", sc->swslist[cnt]);
      printf("\n");
    }

  }
  return(0);
}

/*
 * en_dumpmem: dump the memory
 */

int en_dumpmem(unit, addr, len)

int unit, addr, len;

{
  struct en_softc *sc;
  u_int32_t reg;

  if (unit < 0 || unit > en_cd.cd_ndevs ||
	(sc = (struct en_softc *) en_cd.cd_devs[unit]) == NULL) {
    printf("invalid unit number: %d\n", unit);
    return(0);
  }
  addr = addr & ~3;
  if (addr < MID_RAMOFF || addr + len*4 > MID_MAXOFF || len <= 0) {
    printf("invalid addr/len number: %d, %d\n", addr, len);
    return(0);
  }
  printf("dumping %d words starting at offset 0x%x\n", len, addr);
  while (len--) {
    reg = EN_READ(sc, addr);
    printf("mem[0x%x] = 0x%x\n", addr, reg);
    addr += 4;
  }
  return(0);
}
#endif
