/*-
 * Copyright (c) 1993, 1994 Charles Hannum.
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	from: @(#)isa.c	7.2 (Berkeley) 5/13/91
 *	$Id: isa.c,v 1.41 1994/03/08 13:24:57 mycroft Exp $
 */

/*
 * code to manage AT bus
 *
 * 92/08/18  Frank P. MacLachlan (fpm@crash.cts.com):
 * Fixed uninitialized variable problem and added code to deal
 * with DMA page boundaries in isa_dmarangecheck().  Fixed word
 * mode DMA count compution and reorganized DMA setup code in
 * isa_dmastart()
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/syslog.h>
#include <sys/malloc.h>

#include <vm/vm.h>

#include <machine/cpu.h>
#include <machine/pio.h>
#include <machine/cpufunc.h>

#include <i386/isa/isa_device.h>
#include <i386/isa/isa.h>
#include <i386/isa/icu.h>
#include <i386/isa/ic/i8237.h>
#include <i386/isa/ic/i8042.h>
#include <i386/isa/timerreg.h>
#include <i386/isa/spkr_reg.h>

/* sorry, has to be here, no place else really suitable */
#include <machine/pc/display.h>
u_short *Crtat = (u_short *)MONO_BUF;

/*
 * Register definitions for DMA controller 1 (channels 0..3):
 */
#define	DMA1_CHN(c)	(IO_DMA1 + 1*(2*(c)))	/* addr reg for channel c */
#define	DMA1_SR		(IO_DMA1 + 1*8)		/* status register */
#define	DMA1_SMSK	(IO_DMA1 + 1*10)	/* single mask register */
#define	DMA1_MODE	(IO_DMA1 + 1*11)	/* mode register */
#define	DMA1_FFC	(IO_DMA1 + 1*12)	/* clear first/last FF */

/*
 * Register definitions for DMA controller 2 (channels 4..7):
 */
#define	DMA2_CHN(c)	(IO_DMA2 + 2*(2*(c)))	/* addr reg for channel c */
#define	DMA2_SR		(IO_DMA2 + 2*8)		/* status register */
#define	DMA2_SMSK	(IO_DMA2 + 2*10)	/* single mask register */
#define	DMA2_MODE	(IO_DMA2 + 2*11)	/* mode register */
#define	DMA2_FFC	(IO_DMA2 + 2*12)	/* clear first/last FF */

int config_isadev(struct isa_device *, u_int *);
void config_attach(struct isa_driver *, struct isa_device *);
static void sysbeepstop(int);

/*
 * Configure all ISA devices
 */
void
isa_configure()
{
	struct isa_device *dvp;
	struct isa_driver *dp;

	(void) splhigh();
	INTREN(IRQ_SLAVE);
	enable_intr();

	for (dvp = isa_devtab_tty; config_isadev(dvp, &imask[PIL_TTY]); dvp++)
		;
	for (dvp = isa_devtab_bio; config_isadev(dvp, &imask[PIL_BIO]); dvp++)
		;
	for (dvp = isa_devtab_net; config_isadev(dvp, &imask[PIL_IMP]); dvp++)
		;
	for (dvp = isa_devtab_null; config_isadev(dvp, (u_int *) NULL); dvp++)
		;

	printf("biomask %x ttymask %x impmask %x\n",
	       imask[PIL_BIO], imask[PIL_TTY], imask[PIL_IMP]);

	imask[PIL_AST] |= 0x80000000;	/* must be non-zero */
	imask[PIL_IMP] |= imask[PIL_AST];
	imask[PIL_TTY] |= imask[PIL_AST];
	imask[PIL_BIO] |= imask[PIL_AST];
	imask[PIL_CLOCK] |= imask[PIL_AST];

	spl0();
}

/*
 * Configure an ISA device.
 */
int
config_isadev(isdp, mp)
	struct isa_device *isdp;
	u_int *mp;
{
	struct isa_driver *dp;
 
	if (dp = isdp->id_driver) {
		if (isdp->id_maddr) {
			extern u_int atdevbase;

			isdp->id_maddr -= 0xa0000; /* XXX should be a define */
			isdp->id_maddr += atdevbase;
		}
		isdp->id_alive = (*dp->probe)(isdp);
		if (isdp->id_irq == (u_short)-1)
			isdp->id_alive = 0;
		/*
		 * Only print the I/O address range if id_alive != -1
		 * Right now this is a temporary fix just for the new
		 * NPX code so that if it finds a 486 that can use trap
		 * 16 it will not report I/O addresses.
		 * Rod Grimes 04/26/94
		 *
		 * XXX -- cgd
		 */
		if (isdp->id_alive) {
			printf("%s%d", dp->name, isdp->id_unit);
			if (isdp->id_iobase) {
				printf(" at 0x%x", isdp->id_iobase);
				if ((isdp->id_iobase + isdp->id_alive - 1) !=
				    isdp->id_iobase)
					printf("-0x%x", isdp->id_iobase +
					    isdp->id_alive - 1);
			}
			if (isdp->id_irq != 0)
				printf(" irq %d", ffs(isdp->id_irq)-1);
			if (isdp->id_drq != -1)
				printf(" drq %d", isdp->id_drq);
			if (isdp->id_maddr != 0)
				printf(" maddr 0x%x", kvtop(isdp->id_maddr));
			if (isdp->id_msize != 0)
				printf("-0x%x", kvtop(isdp->id_maddr) +
					isdp->id_msize - 1);
			if (isdp->id_flags != 0)
				printf(" flags 0x%x", isdp->id_flags);
			printf(" on isa\n");

			config_attach(dp, isdp);

			if (isdp->id_irq) {
				int intrno;

				intrno = ffs(isdp->id_irq)-1;
				setidt(ICU_OFFSET+intrno, isdp->id_intr,
					 SDT_SYS386IGT, SEL_KPL);
				if(mp)
					INTRMASK(*mp,isdp->id_irq);
				INTREN(isdp->id_irq);
			}
		}
		return (1);
	} else	return(0);
}

void
config_attach(struct isa_driver *dp, struct isa_device *isdp)
{
	extern struct isa_device isa_subdev[];
	struct isa_device *dvp;

	if(isdp->id_masunit==-1) {
		(void)(*dp->attach)(isdp);
		return;
	}

	if(isdp->id_masunit==0) {
		for(dvp = isa_subdev; dvp->id_driver; dvp++) {
			if (dvp->id_driver != dp)
				continue;
			if (dvp->id_masunit != isdp->id_unit)
				continue;
			if (dvp->id_physid == -1)
				continue;
			dvp->id_alive = (*dp->attach)(dvp);
		}
		for(dvp = isa_subdev; dvp->id_driver; dvp++) {
			if (dvp->id_driver != dp)
				continue;
			if (dvp->id_masunit != isdp->id_unit)
				continue;
			if (dvp->id_physid != -1)
				continue;
			dvp->id_alive = (*dp->attach)(dvp);
		}
		return;
	}
	printf("id_masunit has weird value\n");
}


#define	IDTVEC(name)	__CONCAT(X,name)
/* default interrupt vector table entries */
extern	IDTVEC(intr0), IDTVEC(intr1), IDTVEC(intr2), IDTVEC(intr3),
	IDTVEC(intr4), IDTVEC(intr5), IDTVEC(intr6), IDTVEC(intr7),
	IDTVEC(intr8), IDTVEC(intr9), IDTVEC(intr10), IDTVEC(intr11),
	IDTVEC(intr12), IDTVEC(intr13), IDTVEC(intr14), IDTVEC(intr15);

static *defvec[16] = {
	&IDTVEC(intr0), &IDTVEC(intr1), &IDTVEC(intr2), &IDTVEC(intr3),
	&IDTVEC(intr4), &IDTVEC(intr5), &IDTVEC(intr6), &IDTVEC(intr7),
	&IDTVEC(intr8), &IDTVEC(intr9), &IDTVEC(intr10), &IDTVEC(intr11),
	&IDTVEC(intr12), &IDTVEC(intr13), &IDTVEC(intr14), &IDTVEC(intr15) };

/* out of range default interrupt vector gate entry */
extern	IDTVEC(intrdefault);

/*
 * Fill in default interrupt table (in case of spuruious interrupt
 * during configuration of kernel, setup interrupt control unit
 */
void
isa_defaultirq() {
	int i;

	/* icu vectors */
	for (i = NRSVIDT ; i < NRSVIDT+ICU_LEN ; i++)
		setidt(i, defvec[i],  SDT_SYS386IGT, SEL_KPL);
  
	/* out of range vectors */
	for (i = NRSVIDT; i < NIDT; i++)
		setidt(i, &IDTVEC(intrdefault), SDT_SYS386IGT, SEL_KPL);

	/* initialize 8259's */
	outb(IO_ICU1, 0x11);		/* reset; program device, four bytes */
	outb(IO_ICU1+1, NRSVIDT);	/* starting at this vector index */
	outb(IO_ICU1+1, 1<<2);		/* slave on line 2 */
#ifdef AUTO_EOI_1
	outb(IO_ICU1+1, 2 | 1);		/* auto EOI, 8086 mode */
#else
	outb(IO_ICU1+1, 1);		/* 8086 mode */
#endif
	outb(IO_ICU1+1, 0xff);		/* leave interrupts masked */
	outb(IO_ICU1, 0x0a);		/* default to IRR on read */
#ifdef REORDER_IRQ
	outb(IO_ICU1, 0xc0 | (3 - 1));	/* pri order 3-7, 0-2 (com2 first) */
#endif

	outb(IO_ICU2, 0x11);		/* reset; program device, four bytes */
	outb(IO_ICU2+1, NRSVIDT+8);	/* staring at this vector index */
	outb(IO_ICU2+1,2);		/* my slave id is 2 */
#ifdef AUTO_EOI_2
	outb(IO_ICU2+1, 2 | 1);		/* auto EOI, 8086 mode */
#else
	outb(IO_ICU2+1,1);		/* 8086 mode */
#endif
	outb(IO_ICU2+1, 0xff);		/* leave interrupts masked */
	outb(IO_ICU2, 0x0a);		/* default to IRR on read */
}

/* region of physical memory known to be contiguous */
vm_offset_t isaphysmem;
static caddr_t dma_bounce[8];		/* XXX */
static char bounced[8];		/* XXX */
#define MAXDMASZ 512		/* XXX */

/* high byte of address is stored in this port for i-th dma channel */
static short dmapageport[8] =
	{ 0x87, 0x83, 0x81, 0x82, 0x8f, 0x8b, 0x89, 0x8a };

/*
 * isa_dmacascade(): program 8237 DMA controller channel to accept
 * external dma control by a board.
 */
void
isa_dmacascade(chan)
	int chan;
{

#ifdef DIAGNOSTIC
	if (chan < 0 || chan > 7)
		panic("isa_dmacascade: impossible request"); 
#endif

	/* set dma channel mode, and set dma channel mode */
	if ((chan & 4) == 0) {
		outb(DMA1_MODE, DMA37MD_CASCADE | chan);
		outb(DMA1_SMSK, chan);
	} else {
		outb(DMA2_MODE, DMA37MD_CASCADE | (chan & 3));
		outb(DMA2_SMSK, chan & 3);
	}
}

/*
 * isa_dmastart(): program 8237 DMA controller channel, avoid page alignment
 * problems by using a bounce buffer.
 */
void
isa_dmastart(flags, addr, nbytes, chan)
	int flags;
	caddr_t addr;
	vm_size_t nbytes;
	int chan;
{
	vm_offset_t phys;
	int waport;
	caddr_t newaddr;

#ifdef DIAGNOSTIC
	if (chan < 0 || chan > 7 ||
	    ((chan & 4) ? (nbytes >= (1<<17) || nbytes & 1 || (u_int)addr & 1) :
	    (nbytes >= (1<<16))))
		panic("isa_dmastart: impossible request"); 
#endif

	if (isa_dmarangecheck(addr, nbytes, chan)) {
		if (dma_bounce[chan] == 0)
			dma_bounce[chan] =
			    /*(caddr_t)malloc(MAXDMASZ, M_TEMP, M_WAITOK);*/
			    (caddr_t) isaphysmem + NBPG*chan;
		bounced[chan] = 1;
		newaddr = dma_bounce[chan];
		*(int *) newaddr = 0;	/* XXX */
		/* copy bounce buffer on write */
		if ((flags & B_READ) == 0)
			bcopy(addr, newaddr, nbytes);
		addr = newaddr;
	}

	/* translate to physical */
	phys = pmap_extract(pmap_kernel(), (vm_offset_t)addr);

	if ((chan & 4) == 0) {
		/*
		 * Program one of DMA channels 0..3.  These are
		 * byte mode channels.
		 */
		/* set dma channel mode, and reset address ff */
		if (flags & B_READ)
			outb(DMA1_MODE, chan | DMA37MD_SINGLE | DMA37MD_WRITE);
		else
			outb(DMA1_MODE, chan | DMA37MD_SINGLE | DMA37MD_READ);
		outb(DMA1_FFC, 0);

		/* send start address */
		waport =  DMA1_CHN(chan);
		outb(waport, phys);
		outb(waport, phys>>8);
		outb(dmapageport[chan], phys>>16);

		/* send count */
		outb(waport + 1, --nbytes);
		outb(waport + 1, nbytes>>8);

		/* unmask channel */
		outb(DMA1_SMSK, chan | DMA37SM_CLEAR);
	} else {
		/*
		 * Program one of DMA channels 4..7.  These are
		 * word mode channels.
		 */
		/* set dma channel mode, and reset address ff */
		if (flags & B_READ)
			outb(DMA2_MODE, (chan & 3) | DMA37MD_SINGLE | DMA37MD_WRITE);
		else
			outb(DMA2_MODE, (chan & 3) | DMA37MD_SINGLE | DMA37MD_READ);
		outb(DMA2_FFC, 0);

		/* send start address */
		waport = DMA2_CHN(chan & 3);
		outb(waport, phys>>1);
		outb(waport, phys>>9);
		outb(dmapageport[chan], phys>>16);

		/* send count */
		nbytes >>= 1;
		outb(waport + 2, --nbytes);
		outb(waport + 2, nbytes>>8);

		/* unmask channel */
		outb(DMA2_SMSK, (chan & 3) | DMA37SM_CLEAR);
	}
}

void
isa_dmadone(flags, addr, nbytes, chan)
	int flags;
	caddr_t addr;
	vm_size_t nbytes;
	int chan;
{
	u_char tc;

#ifdef DIAGNOSTIC
	if (chan < 0 || chan > 7)
		panic("isa_dmadone: impossible request");
#endif

	/* check that the terminal count was reached */
	if ((chan & 4) == 0)
		tc = inb(DMA1_SR) & (1 << chan);
	else
		tc = inb(DMA2_SR) & (1 << (chan & 3));
	if (tc == 0)
		/* XXX probably should panic or something */
		log(LOG_ERR, "dma channel %d not finished\n", chan);

	/* copy bounce buffer on read */
	if (bounced[chan]) {
		bcopy(dma_bounce[chan], addr, nbytes);
		bounced[chan] = 0;
	}

	/* mask channel */
	if ((chan & 4) == 0)
		outb(DMA1_SMSK, DMA37SM_SET | chan);
	else
		outb(DMA2_SMSK, DMA37SM_SET | (chan & 3));
}

/*
 * Check for problems with the address range of a DMA transfer
 * (non-contiguous physical pages, outside of bus address space,
 * crossing DMA page boundaries).
 * Return true if special handling needed.
 */
int
isa_dmarangecheck(va, length, chan)
	vm_offset_t va;
	u_long length;
	int chan;
{
	vm_offset_t phys, priorpage = 0, endva;
	u_int dma_pgmsk = (chan & 4) ?  ~(128*1024-1) : ~(64*1024-1);

	endva = round_page(va + length);
	for (; va < endva ; va += NBPG) {
		phys = trunc_page(pmap_extract(pmap_kernel(), va));
		if (phys == 0)
			panic("isa_dmacheck: no physical page present");
		if (phys >= (1<<24)) 
			return 1;
		if (priorpage) {
			if (priorpage + NBPG != phys)
				return 1;
			/* check if crossing a DMA page boundary */
			if ((priorpage ^ phys) & dma_pgmsk)
				return 1;
		}
		priorpage = phys;
	}
	return 0;
}

/* head of queue waiting for physmem to become available */
struct buf isa_physmemq;

/* blocked waiting for resource to become free for exclusive use */
static isaphysmemflag;
/* if waited for and call requested when free (B_CALL) */
static void (*isaphysmemunblock)(); /* needs to be a list */

/*
 * Allocate contiguous physical memory for transfer, returning
 * a *virtual* address to region. May block waiting for resource.
 * (assumed to be called at splbio())
 */
caddr_t
isa_allocphysmem(caddr_t va, unsigned length, void (*func)()) {
	
	isaphysmemunblock = func;
	while (isaphysmemflag & B_BUSY) {
		isaphysmemflag |= B_WANTED;
		sleep((caddr_t)&isaphysmemflag, PRIBIO);
	}
	isaphysmemflag |= B_BUSY;

	return((caddr_t)isaphysmem);
}

/*
 * Free contiguous physical memory used for transfer.
 * (assumed to be called at splbio())
 */
void
isa_freephysmem(caddr_t va, unsigned length) {

	isaphysmemflag &= ~B_BUSY;
	if (isaphysmemflag & B_WANTED) {
		isaphysmemflag &= B_WANTED;
		wakeup((caddr_t)&isaphysmemflag);
		if (isaphysmemunblock)
			(*isaphysmemunblock)();
	}
}
	
/*
 * Handle a NMI, possibly a machine check.
 * return true to panic system, false to ignore.
 */
int
isa_nmi(cd) {

	log(LOG_CRIT, "\nNMI port 61 %x, port 70 %x\n", inb(0x61), inb(0x70));
	return(0);
}

/*
 * Caught a stray interrupt, notify
 */
void
isa_strayintr(d) {

	/* DON'T BOTHER FOR NOW! */
	/* for some reason, we get bursts of intr #7, even if not enabled! */
	/*
	 * Well the reason you got bursts of intr #7 is because someone
	 * raised an interrupt line and dropped it before the 8259 could
	 * prioritize it.  This is documented in the intel data book.  This
	 * means you have BAD hardware!  I have changed this so that only
	 * the first 5 get logged, then it quits logging them, and puts
	 * out a special message. rgrimes 3/25/1993
	 */
	extern u_long intrcnt_stray;

	intrcnt_stray++;
	if (intrcnt_stray <= 5)
		log(LOG_ERR,"ISA strayintr %x\n", d);
	if (intrcnt_stray == 5)
		log(LOG_CRIT,"Too many ISA strayintr not logging any more\n");
}

/*
 * Wait "n" microseconds.
 * Relies on timer 1 counting down from (TIMER_FREQ / hz) at TIMER_FREQ Hz.
 * Note: timer had better have been programmed before this is first used!
 * (Note that we use `rate generator' mode, which counts at 1:1; `square
 * wave' mode counts at 2:1).
 */
void
delay(n)
	int n;
{
	int limit, tick, otick;

	/*
	 * Read the counter first, so that the rest of the setup overhead is
	 * counted.
	 */
	otick = gettick();

#ifdef __GNUC__
	/*
	 * Calculate ((n * TIMER_FREQ) / 1e6) using explicit assembler code so
	 * we can take advantage of the intermediate 64-bit quantity to prevent
	 * loss of significance.
	 */
	n -= 5;
	if (n < 0)
		return;
	{register int m;
	__asm __volatile("mul %3"
			 : "=a" (n), "=d" (m)
			 : "0" (n), "r" (TIMER_FREQ));
	__asm __volatile("div %3"
			 : "=a" (n)
			 : "0" (n), "d" (m), "r" (1000000)
			 : "%edx");}
#else
	/*
	 * Calculate ((n * TIMER_FREQ) / 1e6) without using floating point and
	 * without any avoidable overflows.
	 */
	n -= 20;
	{
		int sec = n / 1000000,
		    usec = n % 1000000;
		n = sec * TIMER_FREQ +
		    usec * (TIMER_FREQ / 1000000) +
		    usec * ((TIMER_FREQ % 1000000) / 1000) / 1000 +
		    usec * (TIMER_FREQ % 1000) / 1000000;
	}
#endif

	limit = TIMER_FREQ / hz;

	while (n > 0) {
		tick = gettick();
		if (tick > otick)
			n -= limit - (tick - otick);
		else
			n -= otick - tick;
		otick = tick;
	}
}

int
gettick()
{
	u_char lo, hi;

	/* Don't want someone screwing with the counter while we're here. */
	disable_intr();
	/* Select counter 0 and latch it. */
	outb(TIMER_MODE, TIMER_SEL0 | TIMER_LATCH);
	lo = inb(TIMER_CNTR0);
	hi = inb(TIMER_CNTR0);
	enable_intr();
	return ((hi << 8) | lo);
}

static beeping;
static void
sysbeepstop(int f)
{
	int s = splhigh();

	/* disable counter 2 */
	disable_intr();
	outb(PITAUX_PORT, inb(PITAUX_PORT) & ~PIT_SPKR);
	enable_intr();
	if (f)
		timeout((timeout_t)sysbeepstop, (caddr_t)0, f);
	else
		beeping = 0;

	splx(s);
}

void
sysbeep(int pitch, int period)
{
	int s = splhigh();
	static int last_pitch, last_period;

	if (beeping) {
		untimeout((timeout_t)sysbeepstop, (caddr_t)(last_period/2));
		untimeout((timeout_t)sysbeepstop, (caddr_t)0);
	}
	if (!beeping || last_pitch != pitch) {
		/*
	 	* XXX - move timer stuff to clock.c.
	 	*/
		disable_intr();
		outb(TIMER_MODE, TIMER_SEL2|TIMER_16BIT|TIMER_SQWAVE);
		outb(TIMER_CNTR2, TIMER_DIV(pitch)%256);
		outb(TIMER_CNTR2, TIMER_DIV(pitch)/256);
		outb(PITAUX_PORT, inb(PITAUX_PORT) | PIT_SPKR);	/* enable counter 2 */
		enable_intr();
	}
	last_pitch = pitch;
	beeping = last_period = period;
	timeout((timeout_t)sysbeepstop, (caddr_t)(period/2), period);

	splx(s);
}

/*
 * find an ISA device in a given isa_devtab_* table, given
 * the table to search, the expected id_driver entry, and the unit number.
 *
 * this function is defined in isa_device.h, and this location is debatable;
 * i put it there because it's useless w/o, and directly operates on
 * the other stuff in that file.
 *
 */

struct isa_device *find_isadev(table, driverp, unit)
	struct isa_device *table;
	struct isa_driver *driverp;
	int unit;
{
	if (driverp == NULL) /* sanity check */
		return NULL;

	while ((table->id_driver != driverp) || (table->id_unit != unit)) {
		if (table->id_driver == 0)
			return NULL;
    
		table++;
	}

	return table;
}

/*
 * Return nonzero if a (masked) irq is pending for a given device.
 */
int
isa_irq_pending(dvp)
	struct isa_device *dvp;
{
	unsigned id_irq;

	id_irq = (unsigned short) dvp->id_irq;	/* XXX silly type in struct */
	if (id_irq & 0xff)
		return (inb(IO_ICU1) & id_irq);
	return (inb(IO_ICU2) & (id_irq >> 8));
}
