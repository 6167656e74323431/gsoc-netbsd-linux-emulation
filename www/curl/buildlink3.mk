# $NetBSD: buildlink3.mk,v 1.4 2004/03/26 02:27:56 wiz Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
CURL_BUILDLINK3_MK:=	${CURL_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	curl
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ncurl}
BUILDLINK_PACKAGES+=	curl

.if !empty(CURL_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.curl+=	curl>=7.9.1
BUILDLINK_RECOMMENDED.curl?=	curl>=7.11.0nb1
BUILDLINK_PKGSRCDIR.curl?=	../../www/curl
.endif	# CURL_BUILDLINK3_MK

.include "../../devel/zlib/buildlink3.mk"
.include "../../security/openssl/buildlink3.mk"

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
