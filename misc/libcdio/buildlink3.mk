# $NetBSD: buildlink3.mk,v 1.5 2004/10/03 00:13:00 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
LIBCDIO_BUILDLINK3_MK:=	${LIBCDIO_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libcdio
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibcdio}
BUILDLINK_PACKAGES+=	libcdio

.if !empty(LIBCDIO_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libcdio+=	libcdio>=0.65
BUILDLINK_RECOMMENDED.libcdio+=	libcdio>=0.68nb1
BUILDLINK_PKGSRCDIR.libcdio?=	../../misc/libcdio
.endif	# LIBCDIO_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
