/*
 * Copyright (C) 1993-1996 Wolfgang Solfrank.
 * Copyright (C) 1993-1996 TooLs GmbH.
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
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "ether.h"
#include "bpfilter.h"

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/device.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <kgdb/kgdb.h>
#include <machine/kgdb.h>

int	kgdb_probe __P((struct device *, void *, void *));
void	kgdb_attach __P((struct device *, struct device *, void *));

struct cfdriver kgdbif_cd = {
	NULL, "kgdb", DV_DULL
};

/* For the config system the device doesn't exist */
int
kgdb_probe(parent, match, aux)
	struct device *parent;
	void *match, *aux;
{
	return 0;
}

void
kgdb_attach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	panic("kgdb_attach");
}

static void
kgdbrcpy(kip, sp, dp, l)
	struct kgdb_if *kip;
	char *sp;
	char *dp;
	int l;
{
	int l1;
	
	/* bounce source pointer */
	while (sp >= kip->gotbuf + sizeof kip->gotbuf)
		sp -= sizeof kip->gotbuf;
	l1 = kip->gotbuf + sizeof kip->gotbuf - sp;
	if (l >= l1) {
		kgdbcopy(sp, dp, l1);
		l -= l1;
		dp += l1;
		sp = kip->gotbuf;
	}
	if (l)
		kgdbcopy(sp, dp, l);
}

static void
kgdbwcpy(kip, sp, dp, l)
	struct kgdb_if *kip;
	char *sp;
	char *dp;
	int l;
{
	int l1;
	
	/* bounce destination pointer */
	while (dp >= kip->gotbuf + sizeof kip->gotbuf)
		dp -= sizeof kip->gotbuf;
	l1 = kip->gotbuf + sizeof kip->gotbuf - dp;
	if (l >= l1) {
		kgdbcopy(sp, dp, l1);
		l -= l1;
		sp += l1;
		dp = kip->gotbuf;
	}
	if (l)
		kgdbcopy(sp, dp, l);
}

static int
kgdbread(kip)
	struct kgdb_if *kip;

{
	struct ifnet *ifp = &kip->arp->ac_if;
	struct ether_header *eh;
	struct mbuf *m, **mp, *head = 0;
	int l, len;
	char *buf = kip->got;
	
	kgdbrcpy(kip, buf, &len, sizeof(int));
	buf += sizeof(int);
	kip->got += len + sizeof(int);
	if (kip->got >= kip->gotbuf + sizeof kip->gotbuf)
		kip->got -= sizeof kip->gotbuf;
	if ((kip->gotlen -= len + sizeof(int)) < 0)
		goto bad;
	
	/* Allocate a header mbuf */
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == 0)
		goto bad;
	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = len;
	l = MHLEN;
	mp = &head;

	/*
	 * Pull packet out of buf.
	 */
	while (len > 0) {
		if (head) {
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m == 0)
				goto bad;
			l = MLEN;
		}
		if (len >= MINCLSIZE) {
			MCLGET(m, M_DONTWAIT);
			if (m->m_flags & M_EXT)
				l = MCLBYTES;
		}
		m->m_len = l = min(len, l);
		kgdbrcpy(kip, buf, mtod(m, caddr_t), l);
		buf += l;
		len -= l;
		*mp = m;
		mp = &m->m_next;
	}
	ifp->if_ipackets++;
	eh = mtod(head, struct ether_header *);

#if	NBPFILTER > 0
	/*
	 * Check if there's a bp filter listening on this interface.
	 * If so, hand off the raw packet to bpf.
	 */
	if (kip->arp->ac_if.if_bpf)
		bpf_mtap(kip->arp->ac_if.if_bpf, head);
	
	/*
	 * Note that the interface cannot be in promiscuous mode if
	 * there are no bpf listeners.  And if we are in promiscuous
	 * mode, we have to check if this packet is really ours.
	 */
	if ((ifp->if_flags&IFF_PROMISC)
	    && kgdbcmp(eh->ether_dhost,
		       kip->arp->ac_enaddr,
		       sizeof eh->ether_dhost)
	       != 0
	    && !(eh->ether_dhost[0] & 1)) {	/* !mcast && !bcast */
		m_freem(head);
		return 0;
	}
	
#endif
	
	/*
	 * Fix up data start offset in mbuf to point past ether header
	 */
	m_adj(head, sizeof(struct ether_header));
	
	ether_input(ifp, eh, head);
	return 1;
bad:
	ifp->if_ierrors++;
	if (head)
		m_freem(head);
	/* flush buffer */
	kip->got = kip->gotbuf;
	kip->gotlen = 0;
	return -1;
}

/*
 * How to handle packets arriving during debugging:
 * 0 - drop 'em immediately
 * 1 - deliver 'em just as they would without debugging
 */
#ifdef	__notyet__	/* results in mp_map overflows			XXX */
char kgdbget = 1;
#else
char kgdbget = 0;
#endif

/*
 * Interface driver interrupt handler calls here
 * to get packets buffered by KGDB.
 */
void
kgdbrint(kip, ifp)
	struct kgdb_if *kip;
	struct ifnet *ifp;
{
	if (kip && kip->arp && ifp == &kip->arp->ac_if)
		while (kip->gotlen > 0)
			kgdbread(kip);
}

/*
 * KGDB hands out a packet that it doesn't want
 */
void
kgdbgotpkt(kip, cp, len)
	struct kgdb_if *kip;
	char *cp;
	int len;
{
	char *buf;
	
	if (!kip->arp || !kgdbget)
		return;

	if (kip->gotlen + sizeof(int) + len > sizeof kip->gotbuf)
		return;
	
	buf = kip->got + kip->gotlen;
	kgdbwcpy(kip, &len, buf, sizeof(int));
	buf += sizeof(int);
	kgdbwcpy(kip, cp, buf, len);
	kip->gotlen += sizeof(int) + roundup(len, sizeof(int));
}

/*
 * KGDB wants to know the IP address of its interface
 */
void
kgdbinet(kip)
	struct kgdb_if *kip;
{
	struct ifaddr *ap;
	
	if (kip->arp) {
		for (ap = kip->arp->ac_if.if_addrlist.tqh_first; ap; ap = ap->ifa_list.tqe_next) {
			if (ap->ifa_addr->sa_family == AF_INET) {
				kgdbcopy(&((struct sockaddr_in *)ap->ifa_addr)->sin_addr,
					 kip->myinetaddr, sizeof kip->myinetaddr);
				kip->flags |= KGDB_MYIP;
				return;
			}
		}
	}
}

/*
 * Initialize KGDB Interface handling
 */
int
kgdbifinit(kip, unit)
	struct kgdb_if *kip;
	int unit;
{
	struct cfdata *cfp, *pcfp;
	extern struct cfdata cfdata[];
	short *pp;
	u_char *cp;
	
	/* flush buffer */
	kip->got = kip->gotbuf;
	/* defaults: */
	kip->mtu = ETHERMTU;
	for (cp = kip->hisenetaddr; cp < kip->hisenetaddr + sizeof kip->hisenetaddr;)
		*cp++ = -1;
	for (cp = kip->hisinetaddr; cp < kip->hisinetaddr + sizeof kip->hisinetaddr;)
		*cp++ = -1;
	/* search for interface */
	for (cfp = cfdata; cfp->cf_driver; cfp++) {
		if (strcmp(cfp->cf_driver->cd_name, "kgdb")
		    || cfp->cf_unit != unit)
			continue;
		kip->cfp = cfp;
		for (pp = cfp->cf_parents; *pp >= 0; pp++) {
			pcfp = cfdata + *pp;
			if (pcfp->cf_attach->ca_match((struct device *)0,
						      pcfp,
						      kip)
			    >= 0) {
				printf("KGDB on %s at address %x\n",
				       kip->name, kip->port);
				if (cfp->cf_loc[0]) /* disable interface fro system */
					pcfp->cf_fstate = FSTATE_FOUND;
				return 0;
			}
		}
	}
	return -1;
}
