# $NetBSD: buildlink3.mk,v 1.19 2018/12/09 18:52:13 adam Exp $

BUILDLINK_TREE+=	plasma-framework

.if !defined(PLASMA_FRAMEWORK_BUILDLINK3_MK)
PLASMA_FRAMEWORK_BUILDLINK3_MK:=

BUILDLINK_API_DEPENDS.plasma-framework+=	plasma-framework>=5.21.0
BUILDLINK_ABI_DEPENDS.plasma-framework?=	plasma-framework>=5.47.0nb5
BUILDLINK_PKGSRCDIR.plasma-framework?=		../../x11/plasma-framework

.include "../../devel/kdeclarative/buildlink3.mk"
.include "../../x11/kactivities5/buildlink3.mk"
.include "../../x11/qt5-qtbase/buildlink3.mk"
.include "../../x11/qt5-qtquickcontrols/buildlink3.mk"
.include "../../x11/qt5-qttools/buildlink3.mk"
.endif	# PLASMA_FRAMEWORK_BUILDLINK3_MK

BUILDLINK_TREE+=	-plasma-framework
