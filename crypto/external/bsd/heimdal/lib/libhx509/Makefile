# $NetBSD: Makefile,v 1.8 2023/05/08 22:17:36 christos Exp $

NOLINT=		# defined

.include <bsd.own.mk>
.include <${.CURDIR}/../../Makefile.inc>

.PATH:		${HEIMDIST}/lib/hx509 ${HEIMBASE}/include

LIB=		hx509

SSLBASE=	${NETBSDSRCDIR}/crypto/external/bsd/${EXTERNAL_OPENSSL_SUBDIR}

LIBDPLIBS+=	asn1	${HEIMBASE}/lib/libasn1		\
		com_err	${HEIMBASE}/lib/libcom_err	\
		crypt	${NETBSDSRCDIR}/lib/libcrypt	\
		crypto	${SSLBASE}/lib/libcrypto	\
		roken	${HEIMBASE}/lib/libroken	\
		wind	${HEIMBASE}/lib/libwind

YHEADER=1
YPREFIX=  _hx509_sel_yy
LPREFIX=  _hx509_sel_yy

INCSDIR=	/usr/include/krb5 
INCS+=		hx509.h hx509-protos.h ${ASN1_INCS} ${COMPILE_ET_INCS}

HEIMSRCS = hx509_err.et ocsp.asn1 pkcs10.asn1

SRCS=				\
	ca.c			\
	cert.c			\
	cms.c			\
	collector.c		\
	crypto.c		\
	crypto-ec.c		\
	doxygen.c		\
	env.c			\
	error.c			\
	file.c			\
	keyset.c		\
	ks_dir.c		\
	ks_file.c		\
	ks_keychain.c		\
	ks_mem.c		\
	ks_null.c		\
	ks_p11.c		\
	ks_p12.c		\
	lock.c			\
	name.c			\
	peer.c			\
	print.c			\
	req.c			\
	revoke.c		\
	sel.c			\
	sel-gram.y		\
	sel-lex.l		\
	softp11.c		\
	${BUILT_SOURCES}


CPPFLAGS+=				\
	-I${HEIMDIST}/lib/hx509/ref	\
	-I${HEIMDIST}/lib/asn1

sel-gram.c: ${ASN1_INCS} ${COMPILE_ET_INCS}

ASN1_FILES.ocsp.asn1 =			\
	asn1_OCSPBasicOCSPResponse.x    \
	asn1_OCSPCertID.x               \
	asn1_OCSPCertStatus.x           \
	asn1_OCSPInnerRequest.x         \
	asn1_OCSPKeyHash.x              \
	asn1_OCSPRequest.x              \
	asn1_OCSPResponderID.x          \
	asn1_OCSPResponse.x             \
	asn1_OCSPResponseBytes.x        \
	asn1_OCSPResponseData.x         \
	asn1_OCSPResponseStatus.x       \
	asn1_OCSPSignature.x            \
	asn1_OCSPSingleResponse.x       \
	asn1_OCSPTBSRequest.x           \
	asn1_OCSPVersion.x              \
	asn1_id_pkix_ocsp.x             \
	asn1_id_pkix_ocsp_basic.x       \
	asn1_id_pkix_ocsp_nonce.x

COPTS.cert.c += -Wno-error=deprecated-declarations
COPTS.crypto-ec.c += -Wno-error=deprecated-declarations
COPTS.crypto.c += -Wno-error=deprecated-declarations
COPTS.ks_p11.c += -Wno-error=deprecated-declarations

.include <${HEIMBASE}/Makefile.rules.inc>
.include <bsd.lib.mk>
