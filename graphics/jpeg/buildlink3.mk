# $NetBSD: buildlink3.mk,v 1.6 2004/10/03 00:14:54 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
JPEG_BUILDLINK3_MK:=	${JPEG_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	jpeg
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Njpeg}
BUILDLINK_PACKAGES+=	jpeg

.if !empty(JPEG_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.jpeg+=	jpeg>=6b
BUILDLINK_RECOMMENDED.jpeg+=	jpeg>=6bnb2
BUILDLINK_PKGSRCDIR.jpeg?=	../../graphics/jpeg
.endif	# JPEG_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
