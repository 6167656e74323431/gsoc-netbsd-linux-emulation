/*      $NetBSD: bswap.h,v 1.2 2002/08/13 22:41:36 thorpej Exp $      */

#ifndef _MACHINE_BSWAP_H_
#define	_MACHINE_BSWAP_H_

#define __BSWAP_RENAME
#include <sys/bswap.h>

#ifdef __GNUC__

#include <arm/byte_swap.h>
#define	bswap16(x)	__byte_swap_word(x)
#define	bswap32(x)	__byte_swap_long(x)

#endif /* __GNUC__ */

#endif /* !_MACHINE_BSWAP_H_ */
