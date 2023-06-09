#	$NetBSD: aes.inc,v 1.1.1.2 2023/04/18 14:19:03 christos Exp $
#
#	@(#) Copyright (c) 1995 Simon J. Gerraty
#
#	SRCS extracted from src/crypto/dist/openssl/crypto/aes/Makefile
#

.PATH:	${OPENSSLSRC}/crypto/aes

AES_SRCS ?= aes_core.c aes_cbc.c

AES_SRCS += \
aes_cfb.c \
aes_ecb.c \
aes_ige.c \
aes_misc.c \
aes_ofb.c \
aes_wrap.c

SRCS += ${AES_SRCS}

.for cryptosrc in ${AES_SRCS}
CPPFLAGS.${cryptosrc} += -I${OPENSSLSRC}/crypto/aes ${AESCPPFLAGS}
.endfor

