# $NetBSD: NetBSD-1.5.mk,v 1.1 2000/11/29 16:35:03 tv Exp $
#
# Configuration file for the NetBSD 1.5 binary release.

# sysinst expects the architectures at top level
RELEASE_SUBDIR=		# empty

# BOOTFILE.alpha is absolute
BOOTFILE.alpha=		${EXTFILEDIR}/alpha.bootxx
EXTFILES.alpha=		alpha.bootxx:alpha/binary/sets/base.tgz,./usr/mdec/bootxx_cd9660
INTFILES.alpha=		netbsd.alpha:alpha/installation/instkernel/netbsd.gz \
			boot:alpha/binary/sets/base.tgz,./usr/mdec/boot

# BOOTFILE.i386 is relative to CD staging root
BOOTFILE.i386=		boot.i386
INTFILES.i386=		boot.i386:i386/installation/floppy/boot-big.fs.gz

# macppc has external bootblock generation tool
EXTFILES.macppc=	macppc.ofwboot:macppc/binary/sets/base.tgz,./usr/mdec/ofwboot
INTFILES.macppc=	ofwboot.xcf:macppc/installation/ofwboot.xcf,link \
			netbsd.macppc:macppc/installation/netbsd.ram.gz,link

# BOOTFILE.pmax is absolute
BOOTFILE.pmax=		${EXTFILEDIR}/pmax.bootxx
EXTFILES.pmax=		pmax.bootxx:pmax/binary/sets/base.tgz,./usr/mdec/bootxx_cd9660
INTFILES.pmax=		netbsd.pmax:pmax/binary/kernel/install.gz,link \
			boot.pmax:pmax/binary/sets/base.tgz,./usr/mdec/boot.pmax

# BOOTFILE.sparc is absolute
BOOTFILE.sparc=		${EXTFILEDIR}/sparc-boot.fs
EXTFILES.sparc=		sparc-boot.fs:sparc/installation/bootfs/boot.fs.gz
INTFILES.sparc=		installation/bootfs/instfs.tgz:sparc/installation/bootfs/instfs.tgz,link
INTDIRS.sparc=		installation/bootfs
MKISOFS_ARGS.sparc=	-hide-hfs ./installation -hide-joliet ./installation

# BOOTFILE.sparc64 is absolute
BOOTFILE.sparc64=	${EXTFILEDIR}/sparc64-boot.fs
EXTFILES.sparc64=	sparc64-boot.fs:sparc64/installation/ramdisk/ramdisk.fs.gz

# BOOTFILE.sun3 is absolute
BOOTFILE.sun3=		${EXTFILEDIR}/sun3-boot.fs
EXTFILES.sun3=		sun3-boot.fs:sun3/installation/miniroot/miniroot.gz

# BOOTFILE.vax is absolute
BOOTFILE.vax=		${EXTFILEDIR}/vax.xxboot
EXTFILES.vax=		vax.xxboot:vax/binary/sets/base.tgz,./usr/mdec/hpboot
INTFILES.vax=		netbsd.vax:vax/installation/netboot/netbsd.ram.gz,link \
			boot.vax:vax/binary/sets/base.tgz,./usr/mdec/boot
