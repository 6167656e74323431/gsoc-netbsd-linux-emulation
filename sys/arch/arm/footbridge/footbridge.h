/*      $NetBSD: footbridge.h,v 1.1 2002/01/05 22:41:47 chris Exp $  */

#ifndef _FOOTBRIDGE_H_
#define _FOOTBRIDGE_H_

#include <sys/termios.h>
#include <arm/bus.h>
void footbridge_pci_bs_tag_init __P((void));
void footbridge_sa110_cc_setup	__P((void));
void footbridge_create_io_bs_tag __P((struct bus_space *, void *));
void footbridge_create_mem_bs_tag __P((struct bus_space *, void *));
int fcomcnattach __P((u_int, int, tcflag_t));
int fcomcndetach __P((void));

#endif
