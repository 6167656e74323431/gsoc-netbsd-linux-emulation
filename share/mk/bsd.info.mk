#	$NetBSD: bsd.info.mk,v 1.37 2004/01/29 01:48:45 lukem Exp $

.include <bsd.init.mk>

##### Basic targets
cleandir:	cleaninfo
realinstall:	infoinstall

##### Default values
INFOFLAGS?=

INFOFILES?=

##### Build rules
.if ${MKINFO} != "no"

INFOFILES=	${TEXINFO:C/\.te?xi(nfo)?$/.info/}

realall:	${INFOFILES}
.NOPATH:	${INFOFILES}

.SUFFIXES: .txi .texi .texinfo .info

.txi.info .texi.info .texinfo.info:
	${_MKTARGET_CREATE}
	${TOOL_MAKEINFO} ${INFOFLAGS} --no-split -o ${.TARGET} ${.IMPSRC}

.endif # ${MKINFO} != "no"

##### Install rules
infoinstall::	# ensure existence
.PHONY:		infoinstall

.if ${MKINFO} != "no"

INFODIRFILE=${DESTDIR}${INFODIR}/dir

# serialize access to ${INFODIRFILE}; needed for parallel makes
__infoinstall: .USE
	${_MKTARGET_INSTALL}
	${INSTALL_FILE} \
	    -o ${INFOOWN_${.ALLSRC:T}:U${INFOOWN}} \
	    -g ${INFOGRP_${.ALLSRC:T}:U${INFOGRP}} \
	    -m ${INFOMODE_${.ALLSRC:T}:U${INFOMODE}} \
	    ${SYSPKGTAG} ${.ALLSRC} ${.TARGET}
	@[ -f ${INFODIRFILE} ] &&					\
	while ! ln ${INFODIRFILE} ${INFODIRFILE}.lock 2> /dev/null;	\
		do sleep 1; done;					\
	${TOOL_INSTALL_INFO} -d ${INFODIRFILE} -r ${.TARGET} 2> /dev/null; \
	${TOOL_INSTALL_INFO} -d ${INFODIRFILE} ${.TARGET};		\
	rm -f ${INFODIRFILE}.lock


.for F in ${INFOFILES:O:u}
_FDIR:=		${INFODIR_${F}:U${INFODIR}}		# dir overrides
_FNAME:=	${INFONAME_${F}:U${INFONAME:U${F:T}}}	# name overrides
_F:=		${DESTDIR}${_FDIR}/${_FNAME}		# installed path

.if ${MKUPDATE} == "no"
${_F}!		${F} __infoinstall			# install rule
.if !defined(BUILD) && !make(all) && !make(${F})
${_F}!		.MADE					# no build at install
.endif
.else
${_F}:		${F} __infoinstall			# install rule
.if !defined(BUILD) && !make(all) && !make(${F})
${_F}:		.MADE					# no build at install
.endif
.endif

infoinstall::	${_F}
.PRECIOUS:	${_F}					# keep if install fails
.endfor

.undef _FDIR
.undef _FNAME
.undef _F
.endif # ${MKINFO} != "no"

##### Clean rules
CLEANFILES+=	${INFOFILES}

cleaninfo: .PHONY
.if !empty(CLEANFILES)
	rm -f ${CLEANFILES}
.endif

##### Pull in related .mk logic
.include <bsd.obj.mk>
.include <bsd.sys.mk>

${TARGETS}:	# ensure existence
