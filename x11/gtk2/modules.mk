# $NetBSD: modules.mk,v 1.3 2004/01/26 14:59:46 jmmv Exp $
#
# This Makefile fragment is intended to be included by packages that install
# GTK2 modules.  It takes care of rebuilding the corresponding databases at
# (de)installation time.
#
# The following variables can be defined:
#    GTK2_IMMODULES - Set to YES if the package installs immodules.
#    GTK2_LOADERS   - Set to YES if the package installs pixbuf loaders.
#

.if !defined(GTK2_MODULES_MK)
GTK2_MODULES_MK=	# defined

GTK_QUERY_IMMODULES=	${BUILDLINK_PREFIX.gtk2}/bin/gtk-query-immodules-2.0
GDK_PIXBUF_QUERY_LOADERS=	${BUILDLINK_PREFIX.gtk2}/bin/gdk-pixbuf-query-loaders

.if defined(GTK2_IMMODULES) && !empty(GTK2_IMMODULES:M[Yy][Ee][Ss])
FILES_SUBST+=		GTK_IMMODULES_DB="${GTK_IMMODULES_DB}"
FILES_SUBST+=		GTK_QUERY_IMMODULES="${GTK_QUERY_IMMODULES}"
GTK_IMMODULES_DB=	${BUILDLINK_PREFIX.gtk2}/libdata/gtk-2.0/gtk.immodules
INSTALL_EXTRA_TMPL+=	../../x11/gtk2/files/immodules.tmpl
DEINSTALL_EXTRA_TMPL+=	../../x11/gtk2/files/immodules.tmpl
USE_PKGINSTALL=		YES
.endif

.if defined(GTK2_LOADERS) && !empty(GTK2_LOADERS:M[Yy][Ee][Ss])
FILES_SUBST+=		GDK_PIXBUF_LOADERS_DB="${GDK_PIXBUF_LOADERS_DB}"
FILES_SUBST+=		GDK_PIXBUF_QUERY_LOADERS="${GDK_PIXBUF_QUERY_LOADERS}"
GDK_PIXBUF_LOADERS_DB=	${BUILDLINK_PREFIX.gtk2}/libdata/gtk-2.0/gdk-pixbuf.loaders
INSTALL_EXTRA_TMPL+=	../../x11/gtk2/files/loaders.tmpl
DEINSTALL_EXTRA_TMPL+=	../../x11/gtk2/files/loaders.tmpl
USE_PKGINSTALL=		YES
.endif

USE_BUILDLINK2=		YES
.include "../../x11/gtk2/buildlink2.mk"

.endif			# GTK2_MODULES_MK
