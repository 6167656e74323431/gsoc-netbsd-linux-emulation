# $NetBSD: buildlink3.mk,v 1.5 2004/03/05 19:25:35 jlam Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
LIBUNGIF_BUILDLINK3_MK:=	${LIBUNGIF_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libungif
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibungif}
BUILDLINK_PACKAGES+=	libungif

.if !empty(LIBUNGIF_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libungif+=	libungif>=4.1.0
BUILDLINK_PKGSRCDIR.libungif?=	../../graphics/libungif
.endif	# LIBUNGIF_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
