# $NetBSD: buildlink2.mk,v 1.7 2003/08/05 13:46:37 drochner Exp $
#
# This Makefile fragment is included by packages that use koffice.
#
# This file was created automatically using createbuildlink 2.4.
#

.if !defined(KOFFICE_BUILDLINK2_MK)
KOFFICE_BUILDLINK2_MK=	# defined

BUILDLINK_PACKAGES+=			koffice
BUILDLINK_DEPENDS.koffice?=		koffice>=1.2.1nb4
BUILDLINK_PKGSRCDIR.koffice?=		../../misc/koffice

EVAL_PREFIX+=	BUILDLINK_PREFIX.koffice=koffice
BUILDLINK_PREFIX.koffice_DEFAULT=	${LOCALBASE}
BUILDLINK_FILES.koffice+=	include/KDChartData.h
BUILDLINK_FILES.koffice+=	include/KDChartListTable.h
BUILDLINK_FILES.koffice+=	include/KDChartTable.h
BUILDLINK_FILES.koffice+=	include/KDChartTableBase.h
BUILDLINK_FILES.koffice+=	include/KDChartVectorTable.h
BUILDLINK_FILES.koffice+=	include/KoApplicationIface.h
BUILDLINK_FILES.koffice+=	include/KoDocumentIface.h
BUILDLINK_FILES.koffice+=	include/KoMainWindowIface.h
BUILDLINK_FILES.koffice+=	include/KoViewIface.h
BUILDLINK_FILES.koffice+=	include/handler.h
BUILDLINK_FILES.koffice+=	include/kcoloractions.h
BUILDLINK_FILES.koffice+=	include/kformulaconfigpage.h
BUILDLINK_FILES.koffice+=	include/kformulacontainer.h
BUILDLINK_FILES.koffice+=	include/kformuladefs.h
BUILDLINK_FILES.koffice+=	include/kformuladocument.h
BUILDLINK_FILES.koffice+=	include/kformulaview.h
BUILDLINK_FILES.koffice+=	include/koApplication.h
BUILDLINK_FILES.koffice+=	include/koCharSelectDia.h
BUILDLINK_FILES.koffice+=	include/koChart.h
BUILDLINK_FILES.koffice+=	include/koChild.h
BUILDLINK_FILES.koffice+=	include/koDocument.h
BUILDLINK_FILES.koffice+=	include/koDocumentChild.h
BUILDLINK_FILES.koffice+=	include/koDocumentInfo.h
BUILDLINK_FILES.koffice+=	include/koDocumentInfoDlg.h
BUILDLINK_FILES.koffice+=	include/koFactory.h
BUILDLINK_FILES.koffice+=	include/koFilter.h
BUILDLINK_FILES.koffice+=	include/koFilterChain.h
BUILDLINK_FILES.koffice+=	include/koFilterManager.h
BUILDLINK_FILES.koffice+=	include/koFind.h
BUILDLINK_FILES.koffice+=	include/koFrame.h
BUILDLINK_FILES.koffice+=	include/koGlobal.h
BUILDLINK_FILES.koffice+=	include/koInsertLink.h
BUILDLINK_FILES.koffice+=	include/koKoolBar.h
BUILDLINK_FILES.koffice+=	include/koMainWindow.h
BUILDLINK_FILES.koffice+=	include/koPageLayoutDia.h
BUILDLINK_FILES.koffice+=	include/koPartSelectAction.h
BUILDLINK_FILES.koffice+=	include/koPartSelectDia.h
BUILDLINK_FILES.koffice+=	include/koPicture.h
BUILDLINK_FILES.koffice+=	include/koPictureCollection.h
BUILDLINK_FILES.koffice+=	include/koPictureFilePreview.h
BUILDLINK_FILES.koffice+=	include/koPictureKey.h
BUILDLINK_FILES.koffice+=	include/koPoint.h
BUILDLINK_FILES.koffice+=	include/koQueryTrader.h
BUILDLINK_FILES.koffice+=	include/koRect.h
BUILDLINK_FILES.koffice+=	include/koReplace.h
BUILDLINK_FILES.koffice+=	include/koRuler.h
BUILDLINK_FILES.koffice+=	include/koSize.h
BUILDLINK_FILES.koffice+=	include/koStore.h
BUILDLINK_FILES.koffice+=	include/koStoreDevice.h
BUILDLINK_FILES.koffice+=	include/koTabChooser.h
BUILDLINK_FILES.koffice+=	include/koTemplateChooseDia.h
BUILDLINK_FILES.koffice+=	include/koTemplateCreateDia.h
BUILDLINK_FILES.koffice+=	include/koToolBox.h
BUILDLINK_FILES.koffice+=	include/koUnit.h
BUILDLINK_FILES.koffice+=	include/koView.h
BUILDLINK_FILES.koffice+=	include/kotoolbutton.h
BUILDLINK_FILES.koffice+=	include/kreportviewer.h
BUILDLINK_FILES.koffice+=	include/kugar.h
BUILDLINK_FILES.koffice+=	include/kugarqt.h
BUILDLINK_FILES.koffice+=	include/mcalcobject.h
BUILDLINK_FILES.koffice+=	include/mfieldobject.h
BUILDLINK_FILES.koffice+=	include/mlabelobject.h
BUILDLINK_FILES.koffice+=	include/mlineobject.h
BUILDLINK_FILES.koffice+=	include/mpagecollection.h
BUILDLINK_FILES.koffice+=	include/mpagedisplay.h
BUILDLINK_FILES.koffice+=	include/mreportdetail.h
BUILDLINK_FILES.koffice+=	include/mreportengine.h
BUILDLINK_FILES.koffice+=	include/mreportobject.h
BUILDLINK_FILES.koffice+=	include/mreportsection.h
BUILDLINK_FILES.koffice+=	include/mreportviewer.h
BUILDLINK_FILES.koffice+=	include/mspecialobject.h
BUILDLINK_FILES.koffice+=	include/mutil.h
BUILDLINK_FILES.koffice+=	include/tkaction.h
BUILDLINK_FILES.koffice+=	include/tkcoloractions.h
BUILDLINK_FILES.koffice+=	include/tkcombobox.h
BUILDLINK_FILES.koffice+=	include/tktoolbarbutton.h
BUILDLINK_FILES.koffice+=	lib/kchart.*
BUILDLINK_FILES.koffice+=	lib/kde3/clipartthumbnail.*
BUILDLINK_FILES.koffice+=	lib/kde3/kfile_koffice.*
BUILDLINK_FILES.koffice+=	lib/kde3/kodocinfopropspage.*
BUILDLINK_FILES.koffice+=	lib/kde3/kofficescan.*
BUILDLINK_FILES.koffice+=	lib/kde3/kofficethumbnail.*
BUILDLINK_FILES.koffice+=	lib/kde3/kwmailmerge_classic.*
BUILDLINK_FILES.koffice+=	lib/kde3/kwmailmerge_qtsqldb.*
BUILDLINK_FILES.koffice+=	lib/kde3/kwmailmerge_qtsqldb_power.*
BUILDLINK_FILES.koffice+=	lib/kde3/libabiwordexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libabiwordimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libamiproexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libamiproimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libapplixspreadimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libapplixwordimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libasciiexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libasciiimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libcsvexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libcsvimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libdbaseimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libdocbookexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libgnumericexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libgnumericimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libhtmlexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libhtmlimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkchartpart.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkfolatexexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkfopngexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkformulapart.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkiviopart.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkounavailpart.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkpresenterpart.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkprkword.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkspelltool.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkspreadcalc.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkspreadhtmlexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkspreadpart.*
BUILDLINK_FILES.koffice+=	lib/kde3/libkwordpart.*
BUILDLINK_FILES.koffice+=	lib/kde3/liblatexexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/liblateximport.*
BUILDLINK_FILES.koffice+=	lib/kde3/liblatexparser.*
BUILDLINK_FILES.koffice+=	lib/kde3/libmswriteimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libolefilter.*
BUILDLINK_FILES.koffice+=	lib/kde3/libpalmdocexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libpalmdocimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libqproimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/librtfexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/librtfimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libthesaurustool.*
BUILDLINK_FILES.koffice+=	lib/kde3/libwmlexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libwmlimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libwpexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libwpimport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libxsltexport.*
BUILDLINK_FILES.koffice+=	lib/kde3/libxsltimport.*
BUILDLINK_FILES.koffice+=	lib/kformulamain.*
BUILDLINK_FILES.koffice+=	lib/kivio.*
BUILDLINK_FILES.koffice+=	lib/koshell.*
BUILDLINK_FILES.koffice+=	lib/kpresenter.*
BUILDLINK_FILES.koffice+=	lib/kspread.*
BUILDLINK_FILES.koffice+=	lib/kword.*
BUILDLINK_FILES.koffice+=	lib/libkdchart.*
BUILDLINK_FILES.koffice+=	lib/libkformula.*
BUILDLINK_FILES.koffice+=	lib/libkivioconnectortool.*
BUILDLINK_FILES.koffice+=	lib/libkivioselecttool.*
BUILDLINK_FILES.koffice+=	lib/libkiviotexttool.*
BUILDLINK_FILES.koffice+=	lib/libkiviozoomtool.*
BUILDLINK_FILES.koffice+=	lib/libkochart.*
BUILDLINK_FILES.koffice+=	lib/libkofficecore.*
BUILDLINK_FILES.koffice+=	lib/libkofficeui.*
BUILDLINK_FILES.koffice+=	lib/libkoscript.*
BUILDLINK_FILES.koffice+=	lib/libkotext.*
BUILDLINK_FILES.koffice+=	lib/libkstore.*
BUILDLINK_FILES.koffice+=	lib/libkugar.*
BUILDLINK_FILES.koffice+=	lib/libkugarpart.*
BUILDLINK_FILES.koffice+=	lib/libkwmailmerge_interface.*
BUILDLINK_FILES.koffice+=	lib/libkwmf.*
BUILDLINK_FILES.koffice+=	lib/libkwordexportfilters.*
BUILDLINK_FILES.koffice+=	lib/straight_connector.ksp

.include "../../mk/gcc.buildlink2.mk"
.include "../../textproc/libxml2/buildlink2.mk"
.include "../../textproc/libxslt/buildlink2.mk"
.include "../../graphics/libart2/buildlink2.mk"
.include "../../meta-pkgs/kde3/buildlink2.mk"
.include "../../x11/kdebase3/buildlink2.mk"

BUILDLINK_TARGETS+=	koffice-buildlink

koffice-buildlink: _BUILDLINK_USE

.endif	# KOFFICE_BUILDLINK2_MK
