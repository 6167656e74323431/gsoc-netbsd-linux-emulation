/*	$NetBSD: optstr.h,v 1.4 2023/04/20 09:04:45 skrll Exp $	*/

/*-
 * Copyright (c) 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_OPTSTR_H_
#define _SYS_OPTSTR_H_

#include "ether.h"

#include <sys/types.h>

#if NETHER > 0
#include <net/if_ether.h>
#endif

/*
 * Prototypes for functions defined in sys/kern/subr_optstr.c.
 */
bool optstr_get(const char *, const char *, char *, size_t);

bool optstr_get_string(const char *, const char *, const char **);
bool optstr_get_number(const char *, const char *, unsigned long *);
bool optstr_get_number_hex(const char *, const char *, unsigned long *);
bool optstr_get_number_binary(const char *, const char *, unsigned long *);

#if NETHER > 0
bool optstr_get_macaddr(const char *, const char *, uint8_t [ETHER_ADDR_LEN]);
#endif

#endif /* _SYS_OPTSTR_H_ */
