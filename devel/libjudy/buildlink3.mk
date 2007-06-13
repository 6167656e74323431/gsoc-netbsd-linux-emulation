# $NetBSD: buildlink3.mk,v 1.1.1.1 2007/06/13 13:28:10 obache Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
LIBJUDY_BUILDLINK3_MK:=	${LIBJUDY_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libjudy
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibjudy}
BUILDLINK_PACKAGES+=	libjudy
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}libjudy

.if !empty(LIBJUDY_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.libjudy+=	libjudy>=1.0.3
BUILDLINK_PKGSRCDIR.libjudy?=	../../devel/libjudy
.endif	# LIBJUDY_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
