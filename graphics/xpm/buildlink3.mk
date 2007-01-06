# $NetBSD: buildlink3.mk,v 1.24 2007/01/06 16:45:17 rillig Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
XPM_BUILDLINK3_MK:=	${XPM_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	xpm
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nxpm}
BUILDLINK_PACKAGES+=	xpm
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}xpm

.if !empty(XPM_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.xpm+=		xpm>=3.4k
BUILDLINK_ABI_DEPENDS.xpm+=	xpm>=3.4knb6
BUILDLINK_PKGSRCDIR.xpm?=	../../graphics/xpm
.endif	# XPM_BUILDLINK3_MK

.include "../../mk/x11.buildlink3.mk"

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
