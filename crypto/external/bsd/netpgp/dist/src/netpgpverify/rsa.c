/*-
 * Copyright (c) 2012 Alistair Crooks <agc@NetBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"

#include <sys/types.h>

#ifdef _KERNEL
# include <sys/kmem.h>
#else
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
#endif

#include "misc.h"
#include "digest.h"
#include "rsa.h"

#ifndef USE_ARG
#define USE_ARG(x)	/*LINTED*/(void)&(x)
#endif

#define RSA_MAX_MODULUS_BITS	16384
#define RSA_SMALL_MODULUS_BITS	3072
#define RSA_MAX_PUBEXP_BITS	64 /* exponent limit enforced for "large" modulus only */

static int
rsa_padding_check_none(uint8_t *to, int tlen, const uint8_t *from, int flen, int num)
{
	USE_ARG(num);
	if (flen > tlen) {
		printf("r too large\n");
		return -1;
	}
	(void) memset(to, 0x0, tlen - flen);
	(void) memcpy(to + tlen - flen, from, flen);
	return tlen;
}

static int
lowlevel_rsa_private_encrypt(int plainc, const unsigned char *plain, unsigned char *encbuf, NETPGPV_RSA *rsa)
{
	PGPV_BIGNUM	*decbn;
	PGPV_BIGNUM	*signedbn;
	uint8_t	*decbuf;
	int	 nbytes;
	int	 signc;
	int	 signedbytes;
	int	 r;

	decbuf = NULL;
	r = -1;
	decbn = PGPV_BN_new();
	signedbn = PGPV_BN_new();
	nbytes = PGPV_BN_num_bytes(rsa->n);
	decbuf = netpgp_allocate(1, nbytes);
	/* add no padding */
	memcpy(decbuf, plain, plainc);
	PGPV_BN_bin2bn(decbuf, nbytes, decbn);
	if (PGPV_BN_cmp(decbn, rsa->n) >= 0) {
		printf("decbn too big\n");
		goto err;
	}
	if (!PGPV_BN_mod_exp(signedbn, decbn, rsa->d, rsa->n, NULL)) {
		printf("bad mod_exp\n");
		goto err;
	}
	signedbytes = PGPV_BN_num_bytes(signedbn);
	signc = PGPV_BN_bn2bin(signedbn, &encbuf[nbytes - signedbytes]);
	memset(encbuf, 0x0, nbytes - signc);
	r = nbytes;
err:
	netpgp_deallocate(decbuf, nbytes);
	PGPV_BN_clear_free(decbn);
	PGPV_BN_clear_free(signedbn);
	return r;
}

static int
lowlevel_rsa_public_encrypt(int plainc, const unsigned char *plain, unsigned char *encbuf, NETPGPV_RSA *rsa)
{
	PGPV_BIGNUM	*decbn;
	PGPV_BIGNUM	*encbn;
	uint8_t	*decbuf;
	int	 nbytes;
	int	 encc;
	int	 r;
	int	 i;

	r = -1;
	decbn = PGPV_BN_new();
	encbn = PGPV_BN_new();
	nbytes = PGPV_BN_num_bytes(rsa->n);
	decbuf = netpgp_allocate(1, nbytes);
	(void) memcpy(decbuf, plain, plainc);
	if (PGPV_BN_bin2bn(decbuf, nbytes, decbn) == NULL) {
		printf("bin2bn failed\n");
		goto err;
	}
	if (PGPV_BN_cmp(decbn, rsa->n) >= 0) {
		printf("PGPV_BN_cmp failed\n");
		goto err;
	}
	if (!PGPV_BN_mod_exp(encbn, decbn, rsa->e, rsa->n, NULL)) {
		printf("PGPV_BN_mod_exp failed\n");
		goto err;
	}
	encc = PGPV_BN_num_bytes(encbn);
	i = PGPV_BN_bn2bin(encbn, &encbuf[nbytes - encc]);
	(void) memset(encbuf, 0x0, nbytes - i);
	r = nbytes;
err:
	if (decbuf) {
		memset(decbuf, 0x0, nbytes);
		netpgp_deallocate(decbuf, nbytes);
	}
	PGPV_BN_clear_free(decbn);
	PGPV_BN_clear_free(encbn);
	return r;
}

static int
lowlevel_rsa_private_decrypt(int enclen, const unsigned char *encbuf, unsigned char *to, NETPGPV_RSA *rsa)
{
	PGPV_BIGNUM	*encbn;
	PGPV_BIGNUM	*decbn;
	uint8_t	*buf;
	int	 nbytes;
	int	 j;
	int	 r;

	r = -1;
	decbn = encbn = NULL;
	buf = NULL;
	if (PGPV_BN_num_bits(rsa->n) > RSA_MAX_MODULUS_BITS) {
		return -1;
	}
	if (PGPV_BN_cmp(rsa->n, rsa->e) <= 0) {
		return -1;
	}
	encbn = PGPV_BN_new();
	decbn = PGPV_BN_new();
	nbytes = PGPV_BN_num_bytes(rsa->n);
	buf = netpgp_allocate(1, nbytes);
	if (enclen > nbytes) {
		printf("bad enclen\n");
		goto err;
	}
	PGPV_BN_bin2bn(encbuf, enclen, encbn);
	if (PGPV_BN_cmp(encbn, rsa->n) >= 0) {
		printf("bad encbn\n");
		goto err;
	}
	PGPV_BN_mod_exp(decbn, encbn, rsa->d, rsa->n, NULL);
	j = PGPV_BN_bn2bin(decbn, buf);
	r = rsa_padding_check_none(to, nbytes, buf, j, nbytes);
err:
	PGPV_BN_clear_free(encbn);
	PGPV_BN_clear_free(decbn);
	netpgp_deallocate(buf, nbytes);
	return r;
}

static int
lowlevel_rsa_public_decrypt(const uint8_t *encbuf, int enclen, uint8_t *dec, const netpgpv_rsa_pubkey_t *rsa)
{
	uint8_t		*decbuf;
	PGPV_BIGNUM		*decbn;
	PGPV_BIGNUM		*encbn;
	int		 decbytes;
	int		 nbytes;
	int		 r;

	nbytes = 0;
	r = -1;
	decbuf = NULL;
	decbn = encbn = NULL;
	if (PGPV_BN_num_bits(rsa->n) > RSA_MAX_MODULUS_BITS) {
		printf("rsa r modulus too large\n");
		goto err;
	}
	if (PGPV_BN_cmp(rsa->n, rsa->e) <= 0) {
		printf("rsa r bad n value\n");
		goto err;
	}
	if (PGPV_BN_num_bits(rsa->n) > RSA_SMALL_MODULUS_BITS &&
	    PGPV_BN_num_bits(rsa->e) > RSA_MAX_PUBEXP_BITS) {
		printf("rsa r bad exponent limit\n");
		goto err;
	}
	if ((encbn = PGPV_BN_new()) == NULL ||
	    (decbn = PGPV_BN_new()) == NULL ||
	    (decbuf = netpgp_allocate(1, nbytes = PGPV_BN_num_bytes(rsa->n))) == NULL) {
		printf("allocation failure\n");
		goto err;
	}
	if (enclen > nbytes) {
		printf("rsa r > mod len\n");
		goto err;
	}
	if (PGPV_BN_bin2bn(encbuf, enclen, encbn) == NULL) {
		printf("null encrypted BN\n");
		goto err;
	}
	if (PGPV_BN_cmp(encbn, rsa->n) >= 0) {
		printf("rsa r data too large for modulus\n");
		goto err;
	}
	if (PGPV_BN_mod_exp(decbn, encbn, rsa->e, rsa->n, NULL) < 0) {
		printf("PGPV_BN_mod_exp < 0\n");
		goto err;
	}
	decbytes = PGPV_BN_num_bytes(decbn);
	(void) PGPV_BN_bn2bin(decbn, decbuf);
	if ((r = rsa_padding_check_none(dec, nbytes, decbuf, decbytes, 0)) < 0) {
		printf("rsa r padding check failed\n");
	}
err:
	PGPV_BN_free(encbn);
	PGPV_BN_free(decbn);
	if (decbuf != NULL) {
		(void) memset(decbuf, 0x0, nbytes);
		netpgp_deallocate(decbuf, nbytes);
	}
	return r;
}

#if 0
/**
  @file rsa_make_key.c
  RSA key generation, Tom St Denis
*/  

/** 
   Create an RSA key
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param size     The size of the modulus (key size) desired (octets)
   @param e        The "e" value (public key).  e==65537 is a good choice
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
static int
rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
{
	void *p, *q, *tmp1, *tmp2, *tmp3;
	int    err;

	LTC_ARGCHK(ltc_mp.name != NULL);
	LTC_ARGCHK(key         != NULL);

	if ((size < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
		return CRYPT_INVALID_KEYSIZE;
	}

	if ((e < 3) || ((e & 1) == 0)) {
		return CRYPT_INVALID_ARG;
	}

	if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
		return err;
	}

	if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != CRYPT_OK) {
		return err;
	}

	/* make primes p and q (optimization provided by Wayne Scott) */
		/* tmp3 = e */
	if ((err = mp_set_int(tmp3, e)) != CRYPT_OK) {
		goto errkey;
	}

	/* make prime "p" */
	do {
		if ((err = rand_prime( p, size/2, prng, wprng)) != CRYPT_OK) {
			goto errkey;
		}
		/* tmp1 = p-1 */
		if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK) {
			goto errkey;
		}
		/* tmp2 = gcd(p-1, e) */
		if ((err = mp_gcd( tmp1,  tmp3,  tmp2)) != CRYPT_OK) {
			goto errkey;
		}
	} while (mp_cmp_d( tmp2, 1) != 0);
	/* while e divides p-1 */

	/* make prime "q" */
	do {
		if ((err = rand_prime( q, size/2, prng, wprng)) != CRYPT_OK) {
			goto errkey;
		}
		/* tmp1 = q-1 */
		if ((err = mp_sub_d( q, 1,  tmp1)) != CRYPT_OK) {
			goto errkey;
		}
		/* tmp2 = gcd(q-1, e) */
		if ((err = mp_gcd( tmp1,  tmp3,  tmp2)) != CRYPT_OK) {
			goto errkey;
		}
	} while (mp_cmp_d( tmp2, 1) != 0);
	/* while e divides q-1 */

	/* tmp1 = lcm(p-1, q-1) */
		/* tmp2 = p-1 */
	if ((err = mp_sub_d( p, 1,  tmp2)) != CRYPT_OK) {
		goto errkey;
	}
	/* tmp1 = q-1 (previous do/while loop) */
		/* tmp1 = lcm(p-1, q-1) */
	if ((err = mp_lcm( tmp1,  tmp2,  tmp1)) != CRYPT_OK) {
		goto errkey;
	}

	/* make key */
	if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL)) != CRYPT_OK) {
		goto errkey;
	}

	/* key->e =  e */
	if ((err = mp_set_int( key->e, e)) != CRYPT_OK) {
		goto errkey;
	}
	/* key->d = 1/e mod lcm(p-1,q-1) */
	if ((err = mp_invmod( key->e,  tmp1,  key->d)) != CRYPT_OK) {
		goto errkey;
	}
	/* key->N = pq */
	if ((err = mp_mul( p,  q,  key->N)) != CRYPT_OK) {
		goto errkey;
	}

	/* optimize for CRT now */
	/* find d mod q-1 and d mod p-1 */
	/* tmp1 = q-1 */
	if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK) {
		goto errkey;
	}
	/* tmp2 = p-1 */
	if ((err = mp_sub_d( q, 1,  tmp2)) != CRYPT_OK) {
		goto errkey;
	}
	/* dP = d mod p-1 */
	if ((err = mp_mod( key->d,  tmp1,  key->dP)) != CRYPT_OK) {
		goto errkey;
	}
	/* dQ = d mod q-1 */
	if ((err = mp_mod( key->d,  tmp2,  key->dQ)) != CRYPT_OK) {
		goto errkey;
	}
	/* qP = 1/q mod p */
	if ((err = mp_invmod( q,  p,  key->qP)) != CRYPT_OK) {
		got oerrkey;
	}

	if ((err = mp_copy( p,  key->p)) != CRYPT_OK) {
		goto errkey;
		}
	if ((err = mp_copy( q,  key->q)) != CRYPT_OK) {
		goto errkey;
	}

	/* set key type (in this case it's CRT optimized) */
	key->type = PK_PRIVATE;

	/* return ok and free temps */
	err = CRYPT_OK;
	goto cleanup;
errkey:
	mp_clear_multi(key->d, key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
cleanup:
	mp_clear_multi(tmp3, tmp2, tmp1, p, q, NULL);
	return err;
}
#endif

#define HASHBUF_LEN	512

#define DSA_MAX_MODULUS_BITS	10000

static int
dsa_do_verify(const unsigned char *calculated, int dgst_len, const netpgpv_dsasig_t *sig, netpgpv_mpi_dsa_t *dsa)
{
	PGPV_BIGNUM		 *M;
	PGPV_BIGNUM		 *W;
	PGPV_BIGNUM		 *t1;
	int		 ret = -1;
	int		 qbits;

	if (dsa->p == NULL || dsa->q == NULL || dsa->g == NULL) {
		return 0;
	}
	M = W = t1 = NULL;
	qbits = PGPV_BN_num_bits(dsa->q);
	switch(qbits) {
	case 160:
	case 224:
	case 256:
		/* openssl sources say these are the valid values */
		/* according to FIPS 186-3 */
		break;
	default:
		printf("dsa: bad # of Q bits\n");
		return 0;
	}
	if (PGPV_BN_num_bits(dsa->p) > DSA_MAX_MODULUS_BITS) {
		printf("dsa: p too large\n");
		return 0;
	}
	/* no love for SHA512? */
	if (dgst_len > SHA256_DIGEST_LENGTH) {
		printf("dsa: digest too long\n");
		return 0;
	}
	ret = 0;
	if ((M = PGPV_BN_new()) == NULL ||
	    (W = PGPV_BN_new()) == NULL ||
	    (t1 = PGPV_BN_new()) == NULL) {
		goto err;
	}
	if (PGPV_BN_is_zero(sig->r) ||
	    PGPV_BN_is_negative(sig->r) ||
	    PGPV_BN_cmp(sig->r, dsa->q) >= 0) {
		goto err;
	}
	if (PGPV_BN_is_zero(sig->s) ||
	    PGPV_BN_is_negative(sig->s) ||
	    PGPV_BN_cmp(sig->s, dsa->q) >= 0) {
		goto err;
	}
	if (PGPV_BN_mod_inverse(W, sig->s, dsa->q, NULL) != MP_OKAY) {
		goto err;
	}
	if (dgst_len > qbits / 8) {
		dgst_len = qbits / 8;
	}
	if (PGPV_BN_bin2bn(calculated, dgst_len, M) == NULL) {
		goto err;
	}
	if (!PGPV_BN_mod_mul(M, M, W, dsa->q, NULL)) {
		goto err;
	}
	if (!PGPV_BN_mod_mul(W, sig->r, W, dsa->q, NULL)) {
		goto err;
	}
	if (!PGPV_BN_mod_exp(dsa->p, t1, dsa->g, M, NULL)) {
		goto err;
	}
	if (!PGPV_BN_div(NULL, M, t1, dsa->q, NULL)) {
		goto err;
	}
	ret = (PGPV_BN_cmp(M, sig->r) == 0);
err:
	if (M) {
		PGPV_BN_free(M);
	}
	if (W) {
		PGPV_BN_free(W);
	}
	if (t1) {
		PGPV_BN_free(t1);
	}
	return ret;
}

/*************************************************************************/

int
netpgpv_RSA_size(const NETPGPV_RSA *rsa)
{
	return (rsa == NULL) ? 0 : PGPV_BN_num_bits(rsa->n);
}

int
netpgpv_DSA_size(const NETPGPV_DSA *dsa)
{
	return (dsa == NULL) ? 0 : PGPV_BN_num_bits(dsa->p);
}

unsigned
netpgpv_dsa_verify(const signature_t *signature,
	const netpgpv_dsa_pubkey_t *pubdsa, const uint8_t *calculated,
	size_t hash_length)
{
	netpgpv_mpi_dsa_t	odsa;
	netpgpv_dsasig_t	osig;
	unsigned		qlen;
	int	             ret;

	if (signature == NULL || pubdsa == NULL || calculated == NULL) {
		return (unsigned)-1;
	}
	(void) memset(&osig, 0x0, sizeof(osig));
	(void) memset(&odsa, 0x0, sizeof(odsa));
	PGPV_BN_copy(osig.r, signature->dsa.r);
	PGPV_BN_copy(osig.s, signature->dsa.s);
	odsa.p = pubdsa->p;
	odsa.q = pubdsa->q;
	odsa.g = pubdsa->g;
	odsa.pub_key = pubdsa->y;
	if ((qlen = PGPV_BN_num_bytes(odsa.q)) < hash_length) {
		hash_length = qlen;
	}
	ret = dsa_do_verify(calculated, (int)hash_length, &signature->dsa, &odsa);
	if (ret < 0) {
		return 0;
	}
	PGPV_BN_free(odsa.p);
	PGPV_BN_free(odsa.q);
	PGPV_BN_free(odsa.g);
	PGPV_BN_free(odsa.pub_key);
	odsa.p = odsa.q = odsa.g = odsa.pub_key = NULL;
	PGPV_BN_free(osig.r);
	PGPV_BN_free(osig.s);
	osig.r = osig.s = NULL;
	return (unsigned)ret;
}

NETPGPV_RSA *
netpgpv_RSA_new(void)
{
	return netpgp_allocate(1, sizeof(NETPGPV_RSA));
}

void
netpgpv_RSA_free(NETPGPV_RSA *rsa)
{
	if (rsa) {
		netpgp_deallocate(rsa, sizeof(*rsa));
	}
}

int
netpgpv_RSA_check_key(NETPGPV_RSA *rsa)
{
	PGPV_BIGNUM	*calcn;
	int	 ret;

	ret = 0;
	if (rsa == NULL || rsa->p == NULL || rsa->q == NULL || rsa->n == NULL) {
		return -1;
	}
	/* check that p and q are coprime, and that n = p*q. */
	if (!PGPV_BN_is_prime(rsa->p, 1, NULL, NULL, NULL) ||
	    !PGPV_BN_is_prime(rsa->q, 1, NULL, NULL, NULL)) {
		return 0;
	}
	calcn = PGPV_BN_new();
        PGPV_BN_mul(calcn, rsa->p, rsa->q, NULL);
	if (PGPV_BN_cmp(calcn, rsa->n) != 0) {
		goto errout;
	}
	/* XXX - check that d*e = 1 mod (p-1*q-1) */
	ret = 1;
errout:
	PGPV_BN_clear_free(calcn);
	return ret;
}

NETPGPV_RSA *
netpgpv_RSA_generate_key(int num, unsigned long e, void (*callback)(int,int,void *), void *cb_arg)
{
	/* STUBBED */
	USE_ARG(num);
	USE_ARG(e);
	USE_ARG(callback);
	USE_ARG(cb_arg);
	printf("RSA_generate_key stubbed\n");
	return netpgpv_RSA_new();
}

/* encrypt */
int
netpgpv_RSA_public_encrypt(int plainc, const unsigned char *plain, unsigned char *encbuf, NETPGPV_RSA *rsa, int padding)
{
	USE_ARG(padding);
	if (plain == NULL || encbuf == NULL || rsa == NULL) {
		return -1;
	}
	return lowlevel_rsa_public_encrypt(plainc, plain, encbuf, rsa);
}

/* decrypt */
int
netpgpv_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, NETPGPV_RSA *rsa, int padding)
{
	USE_ARG(padding);
	if (from == NULL || to == NULL || rsa == NULL) {
		return -1;
	}
	return lowlevel_rsa_private_decrypt(flen, from, to, rsa);
}

/* sign */
int
netpgpv_RSA_private_encrypt(int plainc, const unsigned char *plain, unsigned char *encbuf, NETPGPV_RSA *rsa, int padding)
{
	USE_ARG(padding);
	if (plain == NULL || encbuf == NULL || rsa == NULL) {
		return -1;
	}
	return lowlevel_rsa_private_encrypt(plainc, plain, encbuf, rsa);
}

/* verify */
int
netpgpv_RSA_public_decrypt(int enclen, const unsigned char *enc, unsigned char *dec, NETPGPV_RSA *rsa, int padding)
{
	netpgpv_rsa_pubkey_t	pub;
	int			ret;

	if (enc == NULL || dec == NULL || rsa == NULL) {
		return 0;
	}
	USE_ARG(padding);
	(void) memset(&pub, 0x0, sizeof(pub));
	pub.n = PGPV_BN_dup(rsa->n);
	pub.e = PGPV_BN_dup(rsa->e);
	ret = lowlevel_rsa_public_decrypt(enc, enclen, dec, &pub);
	PGPV_BN_free(pub.n);
	PGPV_BN_free(pub.e);
	return ret;
}

/***********************************************************************/

NETPGPV_DSA *
netpgpv_DSA_new(void)
{
	return netpgp_allocate(1, sizeof(NETPGPV_DSA));
}

void
netpgpv_DSA_free(NETPGPV_DSA *dsa)
{
	if (dsa) {
		netpgp_deallocate(dsa, sizeof(*dsa));
	}
}

NETPGPV_DSA_SIG *
netpgpv_DSA_SIG_new(void)
{
	return netpgp_allocate(1, sizeof(NETPGPV_DSA_SIG));
}

void
netpgpv_DSA_SIG_free(NETPGPV_DSA_SIG *sig)
{
	if (sig) {
		netpgp_deallocate(sig, sizeof(*sig));
	}
}

NETPGPV_DSA_SIG *
netpgpv_DSA_do_sign(const unsigned char *dgst, int dlen, NETPGPV_DSA *dsa)
{
	/* STUBBED */
	USE_ARG(dgst);
	USE_ARG(dlen);
	USE_ARG(dsa);
	printf("DSA_do_sign stubbed\n");
	return netpgpv_DSA_SIG_new();
}

int
netpgpv_DSA_do_verify(const unsigned char *dgst, int dgst_len, NETPGPV_DSA_SIG *sig, NETPGPV_DSA *dsa)
{
	if (dgst == NULL || dgst_len == 0 || sig == NULL || dsa == NULL) {
		return -1;
	}
	return dsa_do_verify(dgst, dgst_len, sig, dsa);
}
