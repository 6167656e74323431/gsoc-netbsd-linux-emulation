# $NetBSD: buildlink3.mk,v 1.3 2004/10/03 00:13:07 tv Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
LIBSIDPLAY_BUILDLINK3_MK:=	${LIBSIDPLAY_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libsidplay
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibsidplay}
BUILDLINK_PACKAGES+=	libsidplay

.if !empty(LIBSIDPLAY_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libsidplay+=		libsidplay>=1.36.38
BUILDLINK_RECOMMENDED.libsidplay+=	libsidplay>=1.36.59nb1
BUILDLINK_PKGSRCDIR.libsidplay?=	../../audio/libsidplay
.endif	# LIBSIDPLAY_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
