# $NetBSD: buildlink3.mk,v 1.7 2008/10/11 22:33:56 dholland Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
LIBFFI_BUILDLINK3_MK:=	${LIBFFI_BUILDLINK3_MK}+

.if ${BUILDLINK_DEPTH} == "+"
BUILDLINK_DEPENDS+=	libffi
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nlibffi}
BUILDLINK_PACKAGES+=	libffi
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}libffi

.if ${LIBFFI_BUILDLINK3_MK} == "+"
BUILDLINK_API_DEPENDS.libffi+=	libffi>=1.20
BUILDLINK_ABI_DEPENDS.libffi+=	libffi>=2.0betanb1
#BUILDLINK_API_DEPENDS.libffi+=	libffi>=3.0.6
BUILDLINK_PKGSRCDIR.libffi?=	../../devel/libffi
.endif	# LIBFFI_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
