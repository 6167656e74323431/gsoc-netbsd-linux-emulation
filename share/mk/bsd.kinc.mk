#	$NetBSD: bsd.kinc.mk,v 1.25 2002/11/26 23:15:54 lukem Exp $

# Variables:
#
# INCSDIR	Directory to install includes into (and/or make, and/or
#		symlink, depending on what's going on).
#
# INCS		Headers to install.
#
# DEPINCS	Headers to install which are built dynamically.
#
# SUBDIR	Subdirectories to enter
#
# SYMLINKS	Symlinks to make (unconditionally), a la bsd.links.mk.
#		Note that the original bits will be 'rm -rf'd rather than
#		just 'rm -f'd, to make the right thing happen with include
#		directories.
#

.include <bsd.init.mk>

##### Basic targets
.PHONY:		incinstall
includes:	${INCS} incinstall

##### Install rules
incinstall::	# ensure existence

# make sure the directory is OK, and install includes.
incinstall::	${DESTDIR}${INCSDIR}
.PRECIOUS:	${DESTDIR}${INCSDIR}
.PHONY:		${DESTDIR}${INCSDIR}

${DESTDIR}${INCSDIR}:
	@if [ ! -d ${.TARGET} ] || [ -h ${.TARGET} ] ; then \
		echo creating ${.TARGET}; \
		/bin/rm -rf ${.TARGET}; \
		${INSTALL_DIR} -o ${BINOWN} -g ${BINGRP} -m 755 \
			${SYSPKGTAG} ${.TARGET}; \
	fi

# -c is forced on here, in order to preserve modtimes for "make depend"
__incinstall: .USE
	@cmp -s ${.ALLSRC} ${.TARGET} > /dev/null 2>&1 || \
	    (echo "${INSTALL_FILE:N-c} -c -o ${BINOWN} -g ${BINGRP} \
		-m ${NONBINMODE} ${SYSPKGTAG} ${.ALLSRC} ${.TARGET}" && \
	     ${INSTALL_FILE:N-c} -c -o ${BINOWN} -g ${BINGRP} \
		-m ${NONBINMODE} ${SYSPKGTAG} ${.ALLSRC} ${.TARGET})

.for F in ${INCS:O:u} ${DEPINCS:O:u}
_F:=		${DESTDIR}${INCSDIR}/${F}		# installed path

.if !defined(UPDATE)
${_F}!		${F} __incinstall			# install rule
.else
${_F}:		${F} __incinstall			# install rule
.endif

incinstall::	${_F}
.PRECIOUS:	${_F}					# keep if install fails
.endfor

.undef _F

.if defined(SYMLINKS) && !empty(SYMLINKS)
incinstall::
	@(set ${SYMLINKS}; \
	 while test $$# -ge 2; do \
		l=$$1; shift; \
		t=${DESTDIR}$$1; shift; \
		if [ -h $$t ]; then \
			cur=`ls -ld $$t | awk '{print $$NF}'` ; \
			if [ "$$cur" = "$$l" ]; then \
				continue ; \
			fi; \
		fi; \
		echo "$$t -> $$l"; \
		${INSTALL_SYMLINK} ${SYSPKGTAG} $$l $$t; \
	 done; )
.endif

##### Pull in related .mk logic
.include <bsd.subdir.mk>
