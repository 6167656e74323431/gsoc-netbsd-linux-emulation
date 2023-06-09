#	$NetBSD: sm2.inc,v 1.1.1.1 2023/04/18 14:19:04 christos Exp $
#
#	SRCS extracted from src/crypto/dist/openssl/crypto/sm2/Makefile
#

.PATH:	${OPENSSLSRC}/crypto/sm2

SM2_SRCS += \
sm2_crypt.c \
sm2_err.c \
sm2_pmeth.c \
sm2_sign.c 

SRCS += ${SM2_SRCS}

.for cryptosrc in ${SM2_SRCS}
CPPFLAGS.${cryptosrc} += -I${OPENSSLSRC}/crypto/sha ${SM3CPPFLAGS}
.endfor
