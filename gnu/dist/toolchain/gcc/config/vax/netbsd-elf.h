/* Definitions of target machine for GNU compiler,
   for vax NetBSD systems.
   Copyright (C) 1998 Free Software Foundation, Inc.

This file is part of GNU CC.

GNU CC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU CC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU CC; see the file COPYING.  If not, write to
the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* This is used on vax platforms that use the ELF format.
   This was taken from the NetBSD/alpha configuration, and modified
   for NetBSD/vax by Matt Thomas <matt@netbsd.org> */

/* Get generic NetBSD ELF definitions.  We will override these if necessary. */

#include <elfos.h>
#define NETBSD_ELF
#include <netbsd.h>
#include <vax/netbsd.h>

#undef SIZE_TYPE
#define SIZE_TYPE "long unsigned int"

#undef PTRDIFF_TYPE
#define PTRDIFF_TYPE "long int"

/* We always use gas here */
#undef  TARGET_GAS
#define TARGET_GAS	(1)

#if 1
#undef  PREFERRED_DEBUGGING_TYPE
#define PREFERRED_DEBUGGING_TYPE DBX_DEBUG
#endif
#undef  DWARF_DEBUGGING_INFO
#undef  DWARF2_DEBUGGING_INFO

/* Function CSE screws up PLT .vs. GOT usage.
 */
#define	NO_FUNCTION_CSE

/* Profiling routines */

/* Redefine this to use %eax instead of %edx.  */
#undef  FUNCTION_PROFILER
#define FUNCTION_PROFILER(FILE, LABELNO)  \
  fprintf (FILE, "\tmovab .LP%d,r0\n\tjsb __mcount+2\n", (LABELNO))

/* Put relocations in the constant pool in the writable data section.  */
#undef  SELECT_RTX_SECTION
#define SELECT_RTX_SECTION(MODE,RTX)		\
{						\
  if ((flag_pic || TARGET_HALFPIC)		\
      && vax_symbolic_operand ((RTX), (MODE)))	\
    data_section ();				\
  else						\
    readonly_data_section ();			\
}

/* Use sjlj exceptions. */
#undef DWARF2_UNWIND_INFO		/* just to be safe */

#undef ASM_FINAL_SPEC

/* Names to predefine in the preprocessor for this target machine. */

/* NetBSD Extension to GNU C: __KPRINTF_ATTRIBUTE__ */

#undef CPP_PREDEFINES
#define CPP_PREDEFINES "\
-D__vax__ -D__NetBSD__ -D__ELF__ \
-Asystem(unix) -Asystem(NetBSD) -Acpu(vax) -Amachine(vax)"

/* The VAX wants no space between the case instruction and the
   jump table.  */
#undef  ASM_OUTPUT_BEFORE_CASE_LABEL
#define ASM_OUTPUT_BEFORE_CASE_LABEL(FILE, PREFIX, NUM, TABLE)

/* This makes use of a hook in varasm.c to mark all external functions
   for us.  We use this to make sure that external functions are correctly
   referenced from the PLT.  */

#define	NO_EXTERNAL_INDIRECT_ADDRESS

/* Get the udiv/urem calls out of the user's namespace */

#undef  UDIVSI3_LIBCALL
#define UDIVSI3_LIBCALL "*__udiv"
#undef  UMODSI3_LIBCALL
#define UMODSI3_LIBCALL "*__urem"

/* Define this macro if references to a symbol must be treated
   differently depending on something about the variable or
   function named by the symbol (such as what section it is in).

   On the VAX, if using PIC, mark a SYMBOL_REF for a non-global
   symbol so that we may use indirect accesses with it.  */

#define ENCODE_SECTION_INFO(DECL)				\
do								\
  {								\
    if ((flag_pic | TARGET_HALFPIC))				\
      {								\
	rtx rtl = (TREE_CODE_CLASS (TREE_CODE (DECL)) != 'd'	\
		   ? TREE_CST_RTL (DECL) : DECL_RTL (DECL));	\
								\
	if (GET_CODE (rtl) == MEM)				\
	  {							\
	    SYMBOL_REF_FLAG (XEXP (rtl, 0))			\
	      = (TREE_CODE_CLASS (TREE_CODE (DECL)) != 'd'	\
		 || ! TREE_PUBLIC (DECL));			\
	  }							\
      }								\
  }								\
while (0)
