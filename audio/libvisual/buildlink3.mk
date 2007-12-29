# $NetBSD: buildlink3.mk,v 1.10 2007/12/29 16:11:38 joerg Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
LIBVISUAL_BUILDLINK3_MK:=	${LIBVISUAL_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libvisual
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibvisual}
BUILDLINK_PACKAGES+=	libvisual
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}libvisual

.if !empty(LIBVISUAL_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.libvisual+=	libvisual>=0.4.0
BUILDLINK_PKGSRCDIR.libvisual?=		../../audio/libvisual
.endif	# LIBVISUAL_BUILDLINK3_MK

.include "../../devel/gettext-lib/buildlink3.mk"

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH:S/+$//}
