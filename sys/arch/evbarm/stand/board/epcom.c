/*	$NetBSD: epcom.c,v 1.6 2022/09/05 14:14:42 tsutsui Exp $	*/

/*
 * Copyright (c) 2004 Jesse Off
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
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * This file provides the cons_init() function and console I/O routines
 * for boards that use the ep93xx ARM SoC UARTs
 */

#include <sys/types.h>
#include <arm/ep93xx/epcomreg.h>
#include <arm/ep93xx/ep93xxreg.h>
#include <lib/libsa/stand.h>

#include "board.h"

#define SCADDR	(EP93XX_APB_HWBASE + EP93XX_APB_SYSCON)
#define	EPCOM_READ(x)		*((volatile uint32_t *) (CONADDR + (EPCOM_ ## x)))
#define	EPCOM_WRITE(x, v)	*((volatile uint32_t *) \
					(CONADDR + (EPCOM_ ## x))) = (v)
#define	SYSCON_READ(x)		*((volatile uint32_t *) \
					(SCADDR + (EP93XX_SYSCON_ ## x)))
#define	SYSCON_WRITE(x, v)	*((volatile uint32_t *) \
					(SCADDR + (EP93XX_SYSCON_ ## x))) = (v)

void
cons_init(void)
{
	unsigned long baud, pwrcnt;

	while(!ISSET(EPCOM_READ(Flag), Flag_TXFE));

	/* Make UART base freq 7 MHz */
	pwrcnt = SYSCON_READ(PwrCnt);
	pwrcnt &= ~(PwrCnt_UARTBAUD);
	SYSCON_WRITE(PwrCnt, pwrcnt);

	baud = EPCOMSPEED2BRD(CONSPEED);
	EPCOM_WRITE(LinCtrlLow, baud & 0xff);
	EPCOM_WRITE(LinCtrlMid, baud >> 8);
	EPCOM_WRITE(LinCtrlHigh, LinCtrlHigh_FEN|LinCtrlHigh_WLEN);
}

int
getchar(void)
{
	while(!ISSET(EPCOM_READ(Flag), Flag_RXFE));
	return (EPCOM_READ(Data) & 0xff);
}

void
putchar(int c)
{
	while(ISSET(EPCOM_READ(Flag), Flag_TXFF));

	if (c == '\n') {
		while(!ISSET(EPCOM_READ(Flag), Flag_TXFE));
		EPCOM_WRITE(Data, '\r');
	} 

	EPCOM_WRITE(Data, c);
}
