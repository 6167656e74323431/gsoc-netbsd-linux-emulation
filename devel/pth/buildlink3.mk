# $NetBSD: buildlink3.mk,v 1.5 2004/03/05 19:25:12 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
PTH_BUILDLINK3_MK:=	${PTH_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	pth
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Npth}
BUILDLINK_PACKAGES+=	pth

.if !empty(PTH_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.pth+=		pth>=2.0.0
BUILDLINK_PKGSRCDIR.pth?=	../../devel/pth
.endif	# PTH_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
