# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative,v 1.12 2003/03/05 06:17:17 mrg Exp 
#
G_libbfd_la_DEPENDENCIES=elfarm-nabi.lo elf32.lo elf.lo elflink.lo elf-strtab.lo elf-eh-frame.lo dwarf1.lo armnetbsd.lo aout32.lo coff-arm.lo cofflink.lo elf32-gen.lo cpu-arm.lo netbsd-core.lo ofiles
G_libbfd_la_OBJECTS=archive.lo archures.lo bfd.lo cache.lo coffgen.lo  corefile.lo format.lo init.lo libbfd.lo opncls.lo reloc.lo section.lo  syms.lo targets.lo hash.lo linker.lo srec.lo binary.lo tekhex.lo  ihex.lo stabs.lo stab-syms.lo merge.lo dwarf2.lo archive64.lo
G_DEFS=-DHAVE_CONFIG_H -I. -I${GNUHOSTDIST}/bfd -I.
G_INCLUDES=-D_GNU_SOURCE  -DNETBSD_CORE   -I. -I${GNUHOSTDIST}/bfd -I${GNUHOSTDIST}/bfd/../include  -I${GNUHOSTDIST}/bfd/../intl -I../intl
G_TDEFAULTS=-DDEFAULT_VECTOR=bfd_elf32_littlearm_vec -DSELECT_VECS='&bfd_elf32_littlearm_vec,&bfd_elf32_bigarm_vec,&armnetbsd_vec,&armcoff_little_vec,&armcoff_big_vec,&bfd_elf32_little_generic_vec,&bfd_elf32_big_generic_vec' -DSELECT_ARCHITECTURES='&bfd_arm_arch' -DHAVE_bfd_elf32_littlearm_vec -DHAVE_bfd_elf32_bigarm_vec -DHAVE_armnetbsd_vec -DHAVE_armcoff_little_vec -DHAVE_armcoff_big_vec -DHAVE_bfd_elf32_little_generic_vec -DHAVE_bfd_elf32_big_generic_vec
