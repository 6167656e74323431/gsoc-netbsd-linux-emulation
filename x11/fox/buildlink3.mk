# $NetBSD: buildlink3.mk,v 1.12 2006/04/17 13:45:58 wiz Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
FOX_BUILDLINK3_MK:=	${FOX_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	fox
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nfox}
BUILDLINK_PACKAGES+=	fox

.if !empty(FOX_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.fox+=		fox>=1.4.16
BUILDLINK_ABI_DEPENDS.fox?=	fox>=1.4.17nb2
BUILDLINK_PKGSRCDIR.fox?=	../../x11/fox
BUILDLINK_INCDIRS.fox?=		include/fox-1.4
.endif	# FOX_BUILDLINK3_MK

.include "../../archivers/bzip2/buildlink3.mk"
.include "../../graphics/glu/buildlink3.mk"
.include "../../graphics/jpeg/buildlink3.mk"
.include "../../graphics/png/buildlink3.mk"
.include "../../graphics/tiff/buildlink3.mk"

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
