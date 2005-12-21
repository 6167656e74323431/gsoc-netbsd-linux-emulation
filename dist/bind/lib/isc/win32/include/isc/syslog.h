/*	$NetBSD: syslog.h,v 1.1.1.3 2005/12/21 23:17:49 christos Exp $	*/

/*
 * Copyright (C) 2004  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* Id: syslog.h,v 1.2.206.1 2004/03/06 08:15:17 marka Exp */

#ifndef ISC_SYSLOG_H
#define ISC_SYSLOG_H 1

#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

isc_result_t
isc_syslog_facilityfromstring(const char *str, int *facilityp);
/*
 * Convert 'str' to the appropriate syslog facility constant.
 *
 * Requires:
 *
 *	'str' is not NULL
 *	'facilityp' is not NULL
 *
 * Returns:
 * 	ISC_R_SUCCESS
 * 	ISC_R_NOTFOUND
 */

ISC_LANG_ENDDECLS

#endif /* ISC_SYSLOG_H */
