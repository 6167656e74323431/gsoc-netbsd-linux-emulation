/*	$NetBSD: arc4.c,v 1.2 2001/11/13 01:40:07 lukem Exp $	*/

/*
 * ARC4 implementation
 *	A Stream Cipher Encryption Algorithm "Arcfour"
 *	<draft-kaukonen-cipher-arcfour-03.txt>
 */

/*        This code illustrates a sample implementation
 *                 of the Arcfour algorithm
 *         Copyright (c) April 29, 1997 Kalle Kaukonen.
 *                    All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that this copyright
 * notice and disclaimer are retained.
 *
 * THIS SOFTWARE IS PROVIDED BY KALLE KAUKONEN AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL KALLE
 * KAUKONEN OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: arc4.c,v 1.2 2001/11/13 01:40:07 lukem Exp $");

#include <sys/types.h>

#include <crypto/arc4/arc4.h>

struct arc4_ctx {
	int	x;
	int	y;
	int	state[256];
	/* was unsigned char, changed to int for performance -- onoe */
};

int
arc4_ctxlen()
{
	return sizeof(struct arc4_ctx);
}

void
arc4_setkey(ctxp, key, keylen)
	void *ctxp;
	unsigned char *key;
	int keylen;
{
	struct arc4_ctx *ctx = ctxp;
	unsigned int i, t, u, ki, si;
	unsigned int *state;

	state = ctx->state;
	ctx->x = 0;
	ctx->y = 0;
	for (i = 0; i < 256; i++)
	       state[i] = i;
	ki = si = 0;
	for (i = 0; i < 256; i++) {
		t = state[i];
		si = (si + key[ki] + t) & 0xff;
		u = state[si];
		state[si] = t;
		state[i] = u;
		if (++ki >= keylen)
			ki = 0;
	}
}

void
arc4_encrypt(ctxp, dst, src, len)
	void *ctxp;
	unsigned char *dst;
	unsigned char *src;
	int len;
{
	struct arc4_ctx *ctx = ctxp;
	unsigned int x, y, sx, sy;
	unsigned int *state;
	const unsigned char *endsrc;

	state = ctx->state;
	x = ctx->x;
	y = ctx->y;
	for (endsrc = src + len; src != endsrc; src++, dst++) {
		x = (x + 1) & 0xff;
		sx = state[x];
		y = (sx + y) & 0xff;
		state[x] = sy = state[y];
		state[y] = sx;
		*dst = *src ^ state[(sx + sy) & 0xff];
	}
	ctx->x = x;
	ctx->y = y;
}

void
arc4_decrypt(ctxp, dst, src, len)
	void *ctxp;
	unsigned char *dst;
	unsigned char *src;
	int len;
{
	arc4_encrypt(ctxp, dst, src, len);
}
