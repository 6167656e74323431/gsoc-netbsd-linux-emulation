# $NetBSD: buildlink3.mk,v 1.2 2004/10/03 00:13:30 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
LIBNET_BUILDLINK3_MK:=	${LIBNET_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	libnet
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibnet}
BUILDLINK_PACKAGES+=	libnet

.if !empty(LIBNET_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.libnet+=	libnet>=1.0.1bnb3
BUILDLINK_RECOMMENDED.libnet+=	libnet>=1.0.1bnb4
BUILDLINK_PKGSRCDIR.libnet?=	../../devel/libnet
.endif	# LIBNET_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
