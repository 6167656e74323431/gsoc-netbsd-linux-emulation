# $NetBSD: buildlink2.mk,v 1.4 2003/12/14 22:10:53 xtraeme Exp $
#
# This Makefile fragment is included by packages that use gnome2-pixmaps.
#
# This file was created automatically using createbuildlink 2.0.
#

.if !defined(GNOME2_PIXMAPS_BUILDLINK2_MK)
GNOME2_PIXMAPS_BUILDLINK2_MK=	# defined

BUILDLINK_PACKAGES+=			gnome2-pixmaps
BUILDLINK_DEPENDS.gnome2-pixmaps?=		gnome2-pixmaps>=2.4.1.1
BUILDLINK_PKGSRCDIR.gnome2-pixmaps?=		../../graphics/gnome2-pixmaps

EVAL_PREFIX+=	BUILDLINK_PREFIX.gnome2-pixmaps=gnome2-pixmaps
BUILDLINK_PREFIX.gnome2-pixmaps_DEFAULT=	${LOCALBASE}

BUILDLINK_TARGETS+=	gnome2-pixmaps-buildlink

gnome2-pixmaps-buildlink: _BUILDLINK_USE

.endif	# GNOME2_PIXMAPS_BUILDLINK2_MK
