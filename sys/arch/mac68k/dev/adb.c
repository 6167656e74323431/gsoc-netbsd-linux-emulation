/*	$NetBSD: adb.c,v 1.1 1994/12/03 23:34:12 briggs Exp $	*/

/*-
 * Copyright (C) 1994	Bradley A. Grantham
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
 *	This product includes software developed by Bradley A. Grantham.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <machine/param.h>
#include <sys/device.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <machine/adbsys.h>
#include "adbvar.h"
#include <machine/keyboard.h>
#include "../mac68k/macrom.h"

/*
 * External keyboard translation matrix
 */
extern unsigned char keyboard[128][3];


/*
 * Event queue definitions
 */
#if !defined(ADB_MAX_EVENTS)
#define ADB_MAX_EVENTS 200	/* Maximum events to be kept in queue */
#endif /* !defined(ADB_MAX_EVENTS) */
	/* maybe should be higher for slower macs? */

static adb_event_t adb_evq[ADB_MAX_EVENTS];	/* ADB event queue */
static int adb_evq_tail = 0;			/* event queue tail */
static int adb_evq_len = 0;			/* event queue length */


/*
 * ADB device state information
 */
static int adb_isopen = 0;	/* Are we queuing events for adb_read? */
int adb_polling = 0;		/* Are we polling?  (Debugger mode) */
static struct selinfo adb_selinfo;	/* select() info */
static struct proc *adb_ioproc = NULL;	/* process to wakeup */


/*
 * Key repeat parameters
 */
static int adb_rptdelay = 20;		/* ticks before auto-repeat */
static int adb_rptinterval = 6;		/* ticks between auto-repeat */
static int adb_repeating = -1;		/* key that is auto-repeating */
static adb_event_t adb_rptevent;	/* event to auto-repeat */


static void
adbattach(parent, dev, aux)
	struct device	*parent, *dev;
	void		*aux;
{
	printf(" (ADB event device)\n");
}


/*
 * Auto-configure parameters
 */
extern int matchbyname();

struct cfdriver adbcd =
      { NULL,
	"adb",
	matchbyname,
	adbattach,
	DV_DULL,
	sizeof(struct device),
	NULL,
	0 };


void adb_enqevent(
	adb_event_t *event)
{
	int s;

	if(adb_evq_tail < 0 || adb_evq_tail >= ADB_MAX_EVENTS)
		panic("adb: event queue tail is out of bounds");

	if(adb_evq_len < 0 || adb_evq_len > ADB_MAX_EVENTS)
		panic("adb: event queue len is out of bounds");

	s = splhigh();

	if(adb_evq_len == ADB_MAX_EVENTS){
		splx(s);
		return;	/* Oh, well... */
	}

	adb_evq[(adb_evq_len + adb_evq_tail) % ADB_MAX_EVENTS] =
		*event;
	adb_evq_len++;

	selwakeup(&adb_selinfo);
	if(adb_ioproc)
		psignal(adb_ioproc, SIGIO);

	splx(s);
}

void adb_handoff(
	adb_event_t *event)
{
	if(adb_isopen && !adb_polling){
		adb_enqevent(event);
	}else{
		if(event->def_addr == 2)
			ite_intr(event);
	}
}


void adb_autorepeat(
	void *keyp)
{
	int key = (int)keyp;

	adb_rptevent.bytes[0] |= 0x80;
	microtime(&adb_rptevent.timestamp);
	adb_handoff(&adb_rptevent);	/* do key up */

	adb_rptevent.bytes[0] &= 0x7f;
	microtime(&adb_rptevent.timestamp);
	adb_handoff(&adb_rptevent);	/* do key down */
	
	if(adb_repeating == key){
		timeout(adb_autorepeat, keyp, adb_rptinterval);
	}
}


void adb_dokeyupdown(
	adb_event_t *event)
{
	int adb_key; 

	if(event->def_addr == 2){
		adb_key = event->u.k.key & 0x7f;
		if(!(event->u.k.key & 0x80) &&
			keyboard[event->u.k.key & 0x7f][0] != 0)
		{
			/* ignore shift & control */
			if(adb_repeating != -1){
				untimeout(adb_autorepeat,
					(void *)adb_rptevent.u.k.key);
			}
			adb_rptevent = *event;
			adb_repeating = adb_key;
			timeout(adb_autorepeat,
				(void *)adb_key, adb_rptdelay);
		}else{
			if(adb_repeating != -1){
				adb_repeating = -1;
				untimeout(adb_autorepeat,
					(void *)adb_rptevent.u.k.key);
			}
			adb_rptevent = *event;
		}
	}
	adb_handoff(event);
}

static adb_ms_buttons = 0;

void adb_keymaybemouse(
	adb_event_t *event)
{
	adb_event_t new_event;
	static optionkey_down = 0;
	
	if(event->u.k.key == ADBK_KEYDOWN(ADBK_OPTION)){
		optionkey_down = 1;
	}else if(event->u.k.key == ADBK_KEYUP(ADBK_OPTION)){ /* keyup */
		optionkey_down = 0;
		if(adb_ms_buttons & 0xfe){
			adb_ms_buttons &= 1;
			new_event.def_addr = ADBADDR_MS;
			new_event.u.m.buttons = adb_ms_buttons;
			new_event.u.m.dx = new_event.u.m.dy = 0;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);
		}
	}else if(optionkey_down){
		if(event->u.k.key == ADBK_KEYDOWN(ADBK_LEFT)){
			adb_ms_buttons |= 2;	/* middle down */
			new_event.def_addr = ADBADDR_MS;
			new_event.u.m.buttons = adb_ms_buttons;
			new_event.u.m.dx = new_event.u.m.dy = 0;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);
		}else if(event->u.k.key == ADBK_KEYUP(ADBK_LEFT)){
			adb_ms_buttons &= ~2;	/* middle up */
			new_event.def_addr = ADBADDR_MS;
			new_event.u.m.buttons = adb_ms_buttons;
			new_event.u.m.dx = new_event.u.m.dy = 0;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);
		}else if(event->u.k.key == ADBK_KEYDOWN(ADBK_RIGHT)){
			adb_ms_buttons |= 4;	/* right down */
			new_event.def_addr = ADBADDR_MS;
			new_event.u.m.buttons = adb_ms_buttons;
			new_event.u.m.dx = new_event.u.m.dy = 0;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);
		}else if(event->u.k.key == ADBK_KEYUP(ADBK_RIGHT)){
			adb_ms_buttons &= ~4;	/* right up */
			new_event.def_addr = ADBADDR_MS;
			new_event.u.m.buttons = adb_ms_buttons;
			new_event.u.m.dx = new_event.u.m.dy = 0;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);
		}else if(ADBK_MODIFIER(event->u.k.key)){ /* ctrl, shift, cmd */
			adb_dokeyupdown(event);
		}else if(event->u.k.key & 0x80){ /* key down */
			new_event = *event;

			new_event.u.k.key = ADBK_KEYDOWN(ADBK_OPTION);		/* send option-down */
			new_event.bytes[0] = new_event.u.k.key;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);

			new_event.u.k.key = event->bytes[0];			/* send key-down */
			new_event.bytes[0] = new_event.u.k.key;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);

			new_event.u.k.key = ADBK_KEYVAL(event->bytes[0]);	/* send key-up */
			adb_dokeyupdown(&new_event);
			microtime(&new_event.timestamp);
			new_event.bytes[0] = new_event.u.k.key;

			new_event.u.k.key = ADBK_OPTION;			/* send option-up */
			new_event.bytes[0] = new_event.u.k.key;
			microtime(&new_event.timestamp);
			adb_dokeyupdown(&new_event);

		}else{
			/* option-keyup -- do nothing */
		}
	}else{
		adb_dokeyupdown(event);
	}
}


void adb_processevent(
	adb_event_t *event)
{
	adb_event_t new_event;

	new_event = *event;

	switch(event->def_addr){
		case ADBADDR_KBD:
			new_event.u.k.key = event->bytes[0];
			new_event.bytes[1] = 0xff;
			adb_keymaybemouse(&new_event);
			if(event->bytes[1] != 0xff){
				new_event.u.k.key = event->bytes[1];
				new_event.bytes[0] = event->bytes[1];
				new_event.bytes[1] = 0xff;
				adb_keymaybemouse(&new_event);
			}
			break;

		case ADBADDR_MS:
			if(! (event->bytes[0] & 0x80)) /* 0 is button down */
				adb_ms_buttons |= 1;
			else
				adb_ms_buttons &= 0xfe;
			new_event.u.m.buttons = adb_ms_buttons;
			new_event.u.m.dx = ((signed int)(event->bytes[1] &
						0x3f)) - ((event->bytes[1] &
						0x40) ?  64 : 0);
			new_event.u.m.dy = ((signed int)(event->bytes[0] &
						0x3f)) - ((event->bytes[0] &
						0x40) ?  64 : 0);
			adb_dokeyupdown(&new_event);
			break;

		default:		/* God only knows. */
			adb_dokeyupdown(event);
	}

}


int adbopen(
	dev_t dev,
	int flag,
	int mode,
	struct proc *p)
{
	register int unit;
	int error = 0;
	int s;
 
	unit = minor(dev);
	if(unit != 0)
		return(ENXIO);
	
	s = splhigh();
	if (adb_isopen)
	{
		splx(s);
		return(EBUSY);
	}
	splx(s);
	adb_evq_tail = 0;
	adb_evq_len = 0;
	adb_isopen = 1;
	adb_ioproc = p;

	return (error);
}


int adbclose(
	dev_t dev,
	int flag,
	int mode,
	struct proc *p)
{
	adb_isopen = 0;
	adb_ioproc = NULL;
	return (0);
}


int adbread(
	dev_t dev,
	struct uio *uio,
	int flag)
{
	int s, error;
	int willfit;
	int total;
	int firstmove;
	int moremove;

	if (uio->uio_resid < sizeof(adb_event_t))
		return (EMSGSIZE);	/* close enough. */

	s = splhigh();
	if(adb_evq_len == 0){
		splx(s);	
		return(0);
	}

	willfit = howmany(uio->uio_resid, sizeof(adb_event_t));
	total = (adb_evq_len < willfit) ? adb_evq_len : willfit;

	firstmove = (adb_evq_tail + total > ADB_MAX_EVENTS)
		? (ADB_MAX_EVENTS - adb_evq_tail) : total;
	
	error = uiomove((caddr_t)&adb_evq[adb_evq_tail],
		firstmove * sizeof(adb_event_t), uio);
	if(error) {
		splx(s);
		return(error);
	}
	moremove = total - firstmove;

	if (moremove > 0){
		error = uiomove((caddr_t)&adb_evq[0],
			moremove * sizeof(adb_event_t), uio);
		if(error) {
			splx(s);
			return(error);
		}
	}

	adb_evq_tail = (adb_evq_tail + total) % ADB_MAX_EVENTS;
	adb_evq_len -= total;
	splx(s);
	return (0);
}

 
int adbwrite(
	dev_t dev,
	struct uio *uio,
	int flag)
{
	return 0;
}


int adbioctl(
	dev_t dev,
	int cmd,
	caddr_t data,
	int flag,
	struct proc *p)
{
	switch(cmd){
		case ADBIOC_DEVSINFO: {
			adb_devinfo_t *di = (void *)data;
			int totaldevs;
			ADBDataBlock adbdata;
			int adbaddr;
			int i;

			/* Initialize to no devices */
			for(i = 0; i < 16; i++)
				di->dev[i].addr = -1;

			totaldevs = CountADBs();
			for(i = 1; i <= totaldevs; i++){
				adbaddr = GetIndADB(&adbdata, i);
					di->dev[adbaddr].addr = adbaddr;
					di->dev[adbaddr].default_addr =
						adbdata.origADBAddr;
					di->dev[adbaddr].handler_id =
						adbdata.devType;
			}

			/* Must call ADB Manager to get devices now */
			break;
		}

		case ADBIOC_GETREPEAT:{
			adb_rptinfo_t *ri = (void *)data;

			ri->delay_ticks = adb_rptdelay;
			ri->interval_ticks = adb_rptinterval;
			break;
		}

		case ADBIOC_SETREPEAT:{
			adb_rptinfo_t *ri = (void *)data;

			adb_rptdelay = ri->delay_ticks;
			adb_rptinterval = ri->interval_ticks;
			break;
		}

		case ADBIOC_RESET:
			adb_init();
			break;

		case ADBIOC_LISTENCMD:{
			adb_listencmd_t *lc = (void *)data;
		}

		default:
			return(EINVAL);
	}
	return(0);
}


int adbselect(
	dev_t dev,
	int rw,
	struct proc *p)
{
	switch (rw) {
		case FREAD:
			/* succeed if there is something to read */
			if (adb_evq_len > 0)
				return (1);
			selrecord(p, &adb_selinfo);
			break;

		case FWRITE:
			return (1);	/* always fails => never blocks */
			break;
	}

	return (0);
}
