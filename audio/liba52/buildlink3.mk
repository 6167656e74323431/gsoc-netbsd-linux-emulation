# $NetBSD: buildlink3.mk,v 1.2 2004/03/05 19:25:07 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
LIBA52_BUILDLINK3_MK:=	${LIBA52_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	liba52
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nliba52}
BUILDLINK_PACKAGES+=	liba52

.if !empty(LIBA52_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.liba52+=	liba52>=0.7.4
BUILDLINK_PKGSRCDIR.liba52?=	../../audio/liba52
.endif	# LIBA52_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
