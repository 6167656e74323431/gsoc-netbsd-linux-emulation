# $NetBSD: buildlink3.mk,v 1.3 2004/03/05 19:25:08 jlam Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
LIBVORBIS_BUILDLINK3_MK:=	${LIBVORBIS_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libvorbis
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibvorbis}
BUILDLINK_PACKAGES+=	libvorbis

.if !empty(LIBVORBIS_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libvorbis+=	libvorbis>=1.0.1
BUILDLINK_PKGSRCDIR.libvorbis?=	../../audio/libvorbis

.include "../../audio/libogg/buildlink3.mk"

.endif	# LIBVORBIS_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
