# $NetBSD: buildlink3.mk,v 1.2 2004/03/05 19:25:08 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
SPEEX_BUILDLINK3_MK:=	${SPEEX_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	speex
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nspeex}
BUILDLINK_PACKAGES+=	speex

.if !empty(SPEEX_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.speex+=	speex>=1.0.2nb1
BUILDLINK_PKGSRCDIR.speex?=	../../audio/speex

.include "../../audio/libogg/buildlink3.mk"

.endif	# SPEEX_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
