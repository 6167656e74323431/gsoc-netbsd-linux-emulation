# $NetBSD: buildlink2.mk,v 1.19 2004/03/26 02:28:01 wiz Exp $

.if !defined(KDELIBS2_BUILDLINK2_MK)
KDELIBS2_BUILDLINK2_MK=	# defined

.include "../../mk/bsd.prefs.mk"

BUILDLINK_PACKAGES+=		kdelibs2
BUILDLINK_PKGBASE.kdelibs2?=	kdelibs
.if !defined(BUILDLINK_DEPENDS.kdelibs2)
BUILDLINK_DEPENDS.kdelibs2+=	kdelibs>=2.2.2nb9
BUILDLINK_DEPENDS.kdelibs2+=	kdelibs<3.0	# qt2-designer-kde wants KDE_2_
.endif
BUILDLINK_RECOMMENDED.kdelibs2?=	kdelibs>=2.2.2nb11
BUILDLINK_PKGSRCDIR.kdelibs2?=	../../x11/kdelibs2

EVAL_PREFIX+=	BUILDLINK_PREFIX.kdelibs2=kdelibs
BUILDLINK_PREFIX.kdelibs2_DEFAULT=	${X11PREFIX}
.if ${OPSYS} == "SunOS"
BUILDLINK_FILES_CMD.kdelibs2= \
	${BUILDLINK_PLIST_CMD.kdelibs2} | ${EGREP} '^(include|lib)'
.else
BUILDLINK_FILES_CMD.kdelibs2= \
	${BUILDLINK_PLIST_CMD.kdelibs2} | ${GREP} '^\(include\|lib\)'
.endif

KDEDIR=				${BUILDLINK_PREFIX.kdelibs2}

BUILDLINK_DEPENDS.audiofile=	libaudiofile>=0.2.3

.include "../../audio/libaudiofile/buildlink2.mk"
.include "../../devel/pcre/buildlink2.mk"
.include "../../security/openssl/buildlink2.mk"
.include "../../x11/qt2-libs/buildlink2.mk"
.include "../../textproc/libxslt/buildlink2.mk"
.include "../../mk/ossaudio.buildlink2.mk"

.if defined(USE_CUPS) && (${USE_CUPS} == "YES")
.  include "../../print/cups/buildlink2.mk"
.endif

BUILDLINK_TARGETS+=	kdelibs2-buildlink

kdelibs2-buildlink: _BUILDLINK_USE

.endif	# KDELIBS2_BUILDLINK2_MK
