/*	$NetBSD: int_mwgwtypes.h,v 1.1 2001/04/14 12:19:50 kleink Exp $	*/

/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Klaus Klein.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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

#ifndef _ARM_INT_MWGWTYPES_H_
#define _ARM_INT_MWGWTYPES_H_

/*
 * 7.18.1 Integer types
 */

/* 7.18.1.2 Minimum-width integer types */

typedef	__signed char		  int_least8_t;
typedef	unsigned char		 uint_least8_t;
typedef	short int		 int_least16_t;
typedef	unsigned short int	uint_least16_t;
typedef	int			 int_least32_t;
typedef	unsigned int		uint_least32_t;
#ifdef __COMPILER_INT64__
typedef	__COMPILER_INT64__	 int_least64_t;
typedef	__COMPILER_UINT64__	uint_least64_t;
#else
/* LONGLONG */
typedef	long long int		 int_least64_t;
/* LONGLONG */
typedef	unsigned long long int	uint_least64_t;
#endif


/* 7.18.1.5 Greatest-width integer types */

#ifdef __COMPILER_INT64__
typedef	__COMPILER_INT64__	      intmax_t;
typedef	__COMPILER_UINT64__	     uintmax_t;
#else
/* LONGLONG */
typedef	long long int		      intmax_t;
/* LONGLONG */
typedef	unsigned long long int	     uintmax_t;
#endif

#endif /* !_ARM_INT_MWGWTYPES_H_ */
