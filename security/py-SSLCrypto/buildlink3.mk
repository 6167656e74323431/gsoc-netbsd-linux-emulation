# $NetBSD: buildlink3.mk,v 1.3 2008/04/25 22:16:20 tnn Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
PY_SSLCRYPTO_BUILDLINK3_MK:=	${PY_SSLCRYPTO_BUILDLINK3_MK}+

.if ${BUILDLINK_DEPTH} == "+"
BUILDLINK_DEPENDS+=	py-SSLCrypto
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Npy-SSLCrypto}
BUILDLINK_PACKAGES+=	py-SSLCrypto
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}py-SSLCrypto

.if ${PY_SSLCRYPTO_BUILDLINK3_MK} == "+"
BUILDLINK_API_DEPENDS.py-SSLCrypto+=	${PYPKGPREFIX}-SSLCrypto>=0.1.1
BUILDLINK_ABI_DEPENDS.py-SSLCrypto?=	${PYPKGPREFIX}-SSLCrypto>=0.1.1nb1
BUILDLINK_PKGSRCDIR.py-SSLCrypto?=	../../security/py-SSLCrypto
.endif	# PY_SSLCRYPTO_BUILDLINK3_MK

#.include "../../security/openssl/buildlink3.mk"

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH:S/+$//}
