/*	$NetBSD: elf_machdep.h,v 1.6 2006/07/08 06:36:42 ross Exp $	*/

#define	ELF32_MACHDEP_ENDIANNESS	ELFDATA2MSB
#define	ELF32_MACHDEP_ID_CASES						\
		case EM_PPC:						\
			break;

#define	ELF64_MACHDEP_ENDIANNESS	ELFDATA2MSB
#define	ELF64_MACHDEP_ID_CASES						\
		case EM_PPC64:						\
			break;

#define	ELF32_MACHDEP_ID	EM_PPC
#define	ELF64_MACHDEP_ID	EM_PPC64

#ifdef _LP64
#define ARCH_ELFSIZE		64	/* MD native binary size */
#else
#define ARCH_ELFSIZE		32	/* MD native binary size */
#endif

#include <machine/reloc.h>		/* XXX */

#define R_TYPE(name) __CONCAT(RELOC_,name)
