# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative,v 1.12 2003/03/05 06:17:17 mrg Exp 
#
G_VERSION=2.13.2.1
G_DEFS=-DHAVE_CONFIG_H -I. -I${GNUHOSTDIST}/binutils -I.
G_INCLUDES=-D_GNU_SOURCE  -I. -I${GNUHOSTDIST}/binutils -I../bfd -I${GNUHOSTDIST}/binutils/../bfd -I${GNUHOSTDIST}/binutils/../include   -I${GNUHOSTDIST}/binutils/../intl -I../intl  -DLOCALEDIR="\"/usr/local/share/locale\""  -Dbin_dummy_emulation=bin_vanilla_emulation
G_PROGRAMS=size objdump ar  strings ranlib objcopy   addr2line  readelf nm-new strip-new cxxfilt
G_man_MANS=addr2line.1  ar.1  dlltool.1  nlmconv.1  nm.1  objcopy.1  objdump.1  ranlib.1  readelf.1  size.1  strings.1  strip.1  windres.1  c++filt.1
G_TEXINFOS=binutils.texi
G_size_OBJECTS=size.o bucomm.o version.o  filemode.o
G_size_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_objdump_OBJECTS=objdump.o budemang.o prdbg.o  rddbg.o debug.o stabs.o ieee.o  rdcoff.o bucomm.o version.o filemode.o
G_objdump_DEPENDENCIES=../opcodes/libopcodes.la ../bfd/libbfd.la  ../libiberty/libiberty.a
G_ar_OBJECTS=arparse.o arlex.o ar.o  not-ranlib.o arsup.o rename.o binemul.o  emul_vanilla.o bucomm.o version.o  filemode.o
G_ar_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_strings_OBJECTS=strings.o bucomm.o version.o  filemode.o
G_strings_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_ranlib_OBJECTS=ar.o is-ranlib.o arparse.o  arlex.o arsup.o rename.o binemul.o  emul_vanilla.o bucomm.o version.o  filemode.o
G_ranlib_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_objcopy_OBJECTS=objcopy.o not-strip.o  rename.o rddbg.o debug.o stabs.o  ieee.o rdcoff.o wrstabs.o bucomm.o  version.o filemode.o
G_objcopy_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_addr2line_OBJECTS=addr2line.o budemang.o  bucomm.o version.o filemode.o
G_addr2line_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_readelf_OBJECTS=readelf.o version.o  unwind-ia64.o
G_readelf_DEPENDENCIES=../libiberty/libiberty.a
G_nm_new_OBJECTS=nm.o budemang.o bucomm.o  version.o filemode.o
G_nm_new_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_strip_new_OBJECTS=objcopy.o is-strip.o  rename.o rddbg.o debug.o stabs.o  ieee.o rdcoff.o wrstabs.o bucomm.o  version.o filemode.o
G_strip_new_DEPENDENCIES=../bfd/libbfd.la ../libiberty/libiberty.a
G_cxxfilt_OBJECTS=
G_cxxfilt_DEPENDENCIES=cplus-dem.o underscore.o  ../libiberty/libiberty.a
