# $NetBSD: buildlink3.mk,v 1.5 2004/10/03 00:13:30 tv Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
LIBGPHOTO2_BUILDLINK3_MK:=	${LIBGPHOTO2_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libgphoto2
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibgphoto2}
BUILDLINK_PACKAGES+=	libgphoto2

.if !empty(LIBGPHOTO2_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libgphoto2+=		libgphoto2>=2.1.2
BUILDLINK_RECOMMENDED.libgphoto2+=	libgphoto2>=2.1.4nb2
BUILDLINK_PKGSRCDIR.libgphoto2?=	../../devel/libgphoto2
.endif	# LIBGPHOTO2_BUILDLINK3_MK

.include "../../devel/gettext-lib/buildlink3.mk"
.include "../../converters/libiconv/buildlink3.mk"
.include "../../graphics/libexif/buildlink3.mk"

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
