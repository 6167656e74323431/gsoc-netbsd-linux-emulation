# $NetBSD: buildlink3.mk,v 1.7 2017/02/28 15:19:59 ryoon Exp $

BUILDLINK_TREE+=	ktexteditor

.if !defined(KTEXTEDITOR_BUILDLINK3_MK)
KTEXTEDITOR_BUILDLINK3_MK:=

BUILDLINK_API_DEPENDS.ktexteditor+=	ktexteditor>=5.21.0
BUILDLINK_ABI_DEPENDS.ktexteditor?=	ktexteditor>=5.25.0nb6
BUILDLINK_PKGSRCDIR.ktexteditor?=	../../devel/ktexteditor

.include "../../devel/kparts/buildlink3.mk"
.include "../../x11/qt5-qtbase/buildlink3.mk"
.endif	# KTEXTEDITOR_BUILDLINK3_MK

BUILDLINK_TREE+=	-ktexteditor
