# $NetBSD: buildlink3.mk,v 1.2 2004/03/05 19:25:35 jlam Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
LIBGDGEDA_BUILDLINK3_MK:=	${LIBGDGEDA_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libgdgeda
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibgdgeda}
BUILDLINK_PACKAGES+=	libgdgeda

.if !empty(LIBGDGEDA_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libgdgeda+=	libgdgeda>=2.0.15
BUILDLINK_PKGSRCDIR.libgdgeda?=	../../graphics/libgdgeda

.include "../../graphics/png/buildlink3.mk"

.endif	# LIBGDGEDA_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
