# $NetBSD: buildlink3.mk,v 1.2 2004/03/05 19:25:07 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GSM_BUILDLINK3_MK:=	${GSM_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	gsm
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ngsm}
BUILDLINK_PACKAGES+=	gsm

.if !empty(GSM_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.gsm+=		gsm>=1.0.10
BUILDLINK_PKGSRCDIR.gsm?=	../../audio/gsm
.endif	# GSM_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
