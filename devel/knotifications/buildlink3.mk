# $NetBSD: buildlink3.mk,v 1.12 2018/12/09 18:52:00 adam Exp $

BUILDLINK_TREE+=	knotifications

.if !defined(KNOTIFICATIONS_BUILDLINK3_MK)
KNOTIFICATIONS_BUILDLINK3_MK:=

BUILDLINK_API_DEPENDS.knotifications+=	knotifications>=5.19.0
BUILDLINK_ABI_DEPENDS.knotifications?=	knotifications>=5.47.0nb4
BUILDLINK_PKGSRCDIR.knotifications?=	../../devel/knotifications

.include "../../devel/kconfig/buildlink3.mk"
.include "../../devel/kcoreaddons/buildlink3.mk"
.include "../../devel/libdbusmenu-qt5/buildlink3.mk"
.include "../../multimedia/phonon-qt5/buildlink3.mk"
.include "../../textproc/kcodecs/buildlink3.mk"
.include "../../x11/kwindowsystem/buildlink3.mk"
.include "../../x11/qt5-qtbase/buildlink3.mk"
.endif	# KNOTIFICATIONS_BUILDLINK3_MK

BUILDLINK_TREE+=	-knotifications
