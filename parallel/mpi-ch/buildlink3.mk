# $NetBSD: buildlink3.mk,v 1.2 2004/03/05 19:25:39 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
MPICH_BUILDLINK3_MK:=	${MPICH_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	mpich
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nmpich}
BUILDLINK_PACKAGES+=	mpich

.if !empty(MPICH_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.mpich+=	mpich>=1.2.5.2
BUILDLINK_PKGSRCDIR.mpich?=	../../parallel/mpi-ch
.endif	# MPICH_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
