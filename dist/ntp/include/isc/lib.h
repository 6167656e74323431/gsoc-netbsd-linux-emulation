/*	$NetBSD: lib.h,v 1.1.1.1 2003/12/04 16:05:22 drochner Exp $	*/

/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Id: lib.h,v 1.7 2001/11/19 03:08:25 mayer Exp */

#ifndef ISC_LIB_H
#define ISC_LIB_H 1

#include <isc/types.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

LIBISC_EXTERNAL_DATA extern isc_msgcat_t *isc_msgcat;

void
isc_lib_initmsgcat(void);
/*
 * Initialize the ISC library's message catalog, isc_msgcat, if it
 * has not already been initialized.
 */

ISC_LANG_ENDDECLS

#endif /* ISC_LIB_H */
