# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative-binutils,v 1.4 2004/12/10 13:57:08 mrg Exp 
#
G_libbfd_la_DEPENDENCIES=elf32-sh.lo elf32.lo elf.lo elflink.lo elf-strtab.lo elf-eh-frame.lo dwarf1.lo coff-sh.lo cofflink.lo elf32-sh64.lo elf32-sh64-com.lo elf64-sh64.lo elf64.lo elf64-gen.lo elf32-gen.lo cpu-sh.lo netbsd-core.lo ofiles
G_libbfd_la_OBJECTS=archive.lo archures.lo bfd.lo bfdio.lo bfdwin.lo  cache.lo coffgen.lo corefile.lo format.lo init.lo libbfd.lo opncls.lo  reloc.lo section.lo syms.lo targets.lo hash.lo linker.lo srec.lo  binary.lo tekhex.lo ihex.lo stabs.lo stab-syms.lo merge.lo dwarf2.lo  simple.lo archive64.lo
G_DEFS=-DHAVE_CONFIG_H -I. -I${GNUHOSTDIST}/bfd -I.
G_INCLUDES=-D_GNU_SOURCE  -DNETBSD_CORE   -I. -I${GNUHOSTDIST}/bfd -I${GNUHOSTDIST}/bfd/../include  -I${GNUHOSTDIST}/bfd/../intl -I../intl
G_TDEFAULTS=-DDEFAULT_VECTOR=bfd_elf32_shlnbsd_vec -DSELECT_VECS='&bfd_elf32_shlnbsd_vec,&bfd_elf32_shnbsd_vec,&shcoff_vec,&shlcoff_vec,&bfd_elf32_sh64lnbsd_vec,&bfd_elf32_sh64nbsd_vec,&bfd_elf64_sh64lnbsd_vec,&bfd_elf64_sh64nbsd_vec,&bfd_elf64_little_generic_vec,&bfd_elf64_big_generic_vec,&bfd_elf32_little_generic_vec,&bfd_elf32_big_generic_vec' -DSELECT_ARCHITECTURES='&bfd_sh_arch' -DHAVE_bfd_elf32_shlnbsd_vec -DHAVE_bfd_elf32_shnbsd_vec -DHAVE_shcoff_vec -DHAVE_shlcoff_vec -DHAVE_bfd_elf32_sh64lnbsd_vec -DHAVE_bfd_elf32_sh64nbsd_vec -DHAVE_bfd_elf64_sh64lnbsd_vec -DHAVE_bfd_elf64_sh64nbsd_vec -DHAVE_bfd_elf64_little_generic_vec -DHAVE_bfd_elf64_big_generic_vec -DHAVE_bfd_elf32_little_generic_vec -DHAVE_bfd_elf32_big_generic_vec
