# $NetBSD: buildlink3.mk,v 1.24 2018/12/09 18:52:14 adam Exp $

BUILDLINK_TREE+=	qt5-qtserialport

.if !defined(QT5_QTSERIALPORT_BUILDLINK3_MK)
QT5_QTSERIALPORT_BUILDLINK3_MK:=

BUILDLINK_API_DEPENDS.qt5-qtserialport+=	qt5-qtserialport>=5.9.1
BUILDLINK_ABI_DEPENDS.qt5-qtserialport+=	qt5-qtserialport>=5.11.2nb2
BUILDLINK_PKGSRCDIR.qt5-qtserialport?=	../../x11/qt5-qtserialport

BUILDLINK_INCDIRS.qt5-qtserialport+=	qt5/include
BUILDLINK_LIBDIRS.qt5-qtserialport+=	qt5/lib
BUILDLINK_LIBDIRS.qt5-qtserialport+=	qt5/plugins

.include "../../x11/qt5-qtbase/buildlink3.mk"
.endif	# QT5_QTSERIALPORT_BUILDLINK3_MK

BUILDLINK_TREE+=	-qt5-qtserialport
