/*
 * WPA Supplicant / wrapper functions for libcrypto
 * Copyright (c) 2004-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"
#include <openssl/opensslv.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "common.h"
#include "crypto.h"

#if OPENSSL_VERSION_NUMBER < 0x00907000
#define DES_key_schedule des_key_schedule
#define DES_cblock des_cblock
#define DES_set_key(key, schedule) des_set_key((key), *(schedule))
#define DES_ecb_encrypt(input, output, ks, enc) \
	des_ecb_encrypt((input), (output), *(ks), (enc))
#endif /* openssl < 0.9.7 */


void md4_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	MD4_CTX ctx;
	size_t i;

	MD4_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		MD4_Update(&ctx, addr[i], len[i]);
	MD4_Final(mac, &ctx);
}


void des_encrypt(const u8 *clear, const u8 *key, u8 *cypher)
{
	u8 pkey[8], next, tmp;
	int i;
	DES_key_schedule ks;

	/* Add parity bits to the key */
	next = 0;
	for (i = 0; i < 7; i++) {
		tmp = key[i];
		pkey[i] = (tmp >> i) | next | 1;
		next = tmp << (7 - i);
	}
	pkey[i] = next | 1;

	DES_set_key(&pkey, &ks);
	DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks,
			DES_ENCRYPT);
}


void md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	MD5_CTX ctx;
	size_t i;

	MD5_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		MD5_Update(&ctx, addr[i], len[i]);
	MD5_Final(mac, &ctx);
}


void sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	SHA_CTX ctx;
	size_t i;

	SHA1_Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA1_Update(&ctx, addr[i], len[i]);
	SHA1_Final(mac, &ctx);
}


#ifndef CONFIG_NO_FIPS186_2_PRF
static void sha1_transform(u8 *state, const u8 data[64])
{
	SHA_CTX context;
	os_memset(&context, 0, sizeof(context));
	os_memcpy(&context.h0, state, 5 * 4);
	SHA1_Transform(&context, data);
	os_memcpy(state, &context.h0, 5 * 4);
}


int fips186_2_prf(const u8 *seed, size_t seed_len, u8 *x, size_t xlen)
{
	u8 xkey[64];
	u32 t[5], _t[5];
	int i, j, m, k;
	u8 *xpos = x;
	u32 carry;

	if (seed_len > sizeof(xkey))
		seed_len = sizeof(xkey);

	/* FIPS 186-2 + change notice 1 */

	os_memcpy(xkey, seed, seed_len);
	os_memset(xkey + seed_len, 0, 64 - seed_len);
	t[0] = 0x67452301;
	t[1] = 0xEFCDAB89;
	t[2] = 0x98BADCFE;
	t[3] = 0x10325476;
	t[4] = 0xC3D2E1F0;

	m = xlen / 40;
	for (j = 0; j < m; j++) {
		/* XSEED_j = 0 */
		for (i = 0; i < 2; i++) {
			/* XVAL = (XKEY + XSEED_j) mod 2^b */

			/* w_i = G(t, XVAL) */
			os_memcpy(_t, t, 20);
			sha1_transform((u8 *) _t, xkey);
			_t[0] = host_to_be32(_t[0]);
			_t[1] = host_to_be32(_t[1]);
			_t[2] = host_to_be32(_t[2]);
			_t[3] = host_to_be32(_t[3]);
			_t[4] = host_to_be32(_t[4]);
			os_memcpy(xpos, _t, 20);

			/* XKEY = (1 + XKEY + w_i) mod 2^b */
			carry = 1;
			for (k = 19; k >= 0; k--) {
				carry += xkey[k] + xpos[k];
				xkey[k] = carry & 0xff;
				carry >>= 8;
			}

			xpos += 20;
		}
		/* x_j = w_0|w_1 */
	}

	return 0;
}
#endif /* CONFIG_NO_FIPS186_2_PRF */


void * aes_encrypt_init(const u8 *key, size_t len)
{
	AES_KEY *ak;
	ak = os_malloc(sizeof(*ak));
	if (ak == NULL)
		return NULL;
	if (AES_set_encrypt_key(key, 8 * len, ak) < 0) {
		os_free(ak);
		return NULL;
	}
	return ak;
}


void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt)
{
	AES_encrypt(plain, crypt, ctx);
}


void aes_encrypt_deinit(void *ctx)
{
	os_free(ctx);
}


void * aes_decrypt_init(const u8 *key, size_t len)
{
	AES_KEY *ak;
	ak = os_malloc(sizeof(*ak));
	if (ak == NULL)
		return NULL;
	if (AES_set_decrypt_key(key, 8 * len, ak) < 0) {
		os_free(ak);
		return NULL;
	}
	return ak;
}


void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain)
{
	AES_decrypt(crypt, plain, ctx);
}


void aes_decrypt_deinit(void *ctx)
{
	os_free(ctx);
}


int crypto_mod_exp(const u8 *base, size_t base_len,
		   const u8 *power, size_t power_len,
		   const u8 *modulus, size_t modulus_len,
		   u8 *result, size_t *result_len)
{
	BIGNUM *bn_base, *bn_exp, *bn_modulus, *bn_result;
	int ret = -1;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		return -1;

	bn_base = BN_bin2bn(base, base_len, NULL);
	bn_exp = BN_bin2bn(power, power_len, NULL);
	bn_modulus = BN_bin2bn(modulus, modulus_len, NULL);
	bn_result = BN_new();

	if (bn_base == NULL || bn_exp == NULL || bn_modulus == NULL ||
	    bn_result == NULL)
		goto error;

	if (BN_mod_exp(bn_result, bn_base, bn_exp, bn_modulus, ctx) != 1)
		goto error;

	*result_len = BN_bn2bin(bn_result, result);
	ret = 0;

error:
	BN_free(bn_base);
	BN_free(bn_exp);
	BN_free(bn_modulus);
	BN_free(bn_result);
	BN_CTX_free(ctx);
	return ret;
}


struct crypto_cipher {
	EVP_CIPHER_CTX enc;
	EVP_CIPHER_CTX dec;
};


struct crypto_cipher * crypto_cipher_init(enum crypto_cipher_alg alg,
					  const u8 *iv, const u8 *key,
					  size_t key_len)
{
	struct crypto_cipher *ctx;
	const EVP_CIPHER *cipher;

	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;

	switch (alg) {
#ifndef OPENSSL_NO_RC4
	case CRYPTO_CIPHER_ALG_RC4:
		cipher = EVP_rc4();
		break;
#endif /* OPENSSL_NO_RC4 */
#ifndef OPENSSL_NO_AES
	case CRYPTO_CIPHER_ALG_AES:
		switch (key_len) {
		case 16:
			cipher = EVP_aes_128_cbc();
			break;
		case 24:
			cipher = EVP_aes_192_cbc();
			break;
		case 32:
			cipher = EVP_aes_256_cbc();
			break;
		default:
			return NULL;
		}
		break;
#endif /* OPENSSL_NO_AES */
#ifndef OPENSSL_NO_DES
	case CRYPTO_CIPHER_ALG_3DES:
		cipher = EVP_des_ede3_cbc();
		break;
	case CRYPTO_CIPHER_ALG_DES:
		cipher = EVP_des_cbc();
		break;
#endif /* OPENSSL_NO_DES */
#ifndef OPENSSL_NO_RC2
	case CRYPTO_CIPHER_ALG_RC2:
		cipher = EVP_rc2_ecb();
		break;
#endif /* OPENSSL_NO_RC2 */
	default:
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ctx->enc);
	EVP_CIPHER_CTX_set_padding(&ctx->enc, 0);
	if (!EVP_EncryptInit_ex(&ctx->enc, cipher, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx->enc, key_len) ||
	    !EVP_EncryptInit_ex(&ctx->enc, cipher, NULL, key, iv)) {
		EVP_CIPHER_CTX_cleanup(&ctx->enc);
		os_free(ctx);
		return NULL;
	}

	EVP_CIPHER_CTX_init(&ctx->dec);
	EVP_CIPHER_CTX_set_padding(&ctx->dec, 0);
	if (!EVP_DecryptInit_ex(&ctx->dec, cipher, NULL, NULL, NULL) ||
	    !EVP_CIPHER_CTX_set_key_length(&ctx->dec, key_len) ||
	    !EVP_DecryptInit_ex(&ctx->dec, cipher, NULL, key, iv)) {
		EVP_CIPHER_CTX_cleanup(&ctx->enc);
		EVP_CIPHER_CTX_cleanup(&ctx->dec);
		os_free(ctx);
		return NULL;
	}

	return ctx;
}


int crypto_cipher_encrypt(struct crypto_cipher *ctx, const u8 *plain,
			  u8 *crypt, size_t len)
{
	int outl;
	if (!EVP_EncryptUpdate(&ctx->enc, crypt, &outl, plain, len))
		return -1;
	return 0;
}


int crypto_cipher_decrypt(struct crypto_cipher *ctx, const u8 *crypt,
			  u8 *plain, size_t len)
{
	int outl;
	outl = len;
	if (!EVP_DecryptUpdate(&ctx->dec, plain, &outl, crypt, len))
		return -1;
	return 0;
}


void crypto_cipher_deinit(struct crypto_cipher *ctx)
{
	EVP_CIPHER_CTX_cleanup(&ctx->enc);
	EVP_CIPHER_CTX_cleanup(&ctx->dec);
	os_free(ctx);
}
