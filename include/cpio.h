/*	$NetBSD: cpio.h,v 1.2 1997/07/30 22:59:57 jtc Exp $	*/

/*-
 * Copyright (c) 1996 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by J.T. Conklin.
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
 *	  Foundation, Inc. and its contributors.
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

#ifndef _CPIO_H_
#define _CPIO_H_

#define C_IRUSR		0000400
#define C_IWUSR		0000200
#define C_IXUSR		0000100
#define C_IRGRP		0000040
#define C_IWGRP		0000020
#define C_IXGRP		0000010
#define C_IROTH		0000004
#define C_IWOTH		0000002
#define C_IXOTH		0000001
#define C_ISUID		0004000
#define C_ISGID		0002000
#define C_ISVTX		0001000
#define C_ISDIR		0040000
#define C_ISFIFO	0010000
#define C_ISREG		0100000
#define C_ISBLK		0060000
#define C_ISCHR		0020000
#define C_ISCTG		0110000
#define C_ISLNK		0120000
#define C_ISSOCK	0140000
 
#define MAGIC		"070707"

#endif /* _CPIO_H_ */
