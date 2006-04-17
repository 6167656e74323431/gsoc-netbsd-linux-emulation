# $NetBSD: buildlink3.mk,v 1.8 2006/04/17 13:46:12 wiz Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GCONFMM_BUILDLINK3_MK:=	${GCONFMM_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	gconfmm
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ngconfmm}
BUILDLINK_PACKAGES+=	gconfmm

.if !empty(GCONFMM_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.gconfmm+=	gconfmm>=2.10.0
BUILDLINK_ABI_DEPENDS.gconfmm?=	gconfmm>=2.14.0nb1
BUILDLINK_PKGSRCDIR.gconfmm?=	../../devel/gconfmm
.endif	# GCONFMM_BUILDLINK3_MK

.include "../../devel/GConf2/buildlink3.mk"
.include "../../x11/gtkmm/buildlink3.mk"

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
