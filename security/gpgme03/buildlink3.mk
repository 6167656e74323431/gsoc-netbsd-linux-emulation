# $NetBSD: buildlink3.mk,v 1.2 2004/03/05 19:25:39 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GPGME_BUILDLINK3_MK:=	${GPGME_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	gpgme
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ngpgme}
BUILDLINK_PACKAGES+=	gpgme

.if !empty(GPGME_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.gpgme+=	gpgme-0.3.[0-9]*
BUILDLINK_PKGSRCDIR.gpgme?=	../../security/gpgme03
.endif	# GPGME_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
