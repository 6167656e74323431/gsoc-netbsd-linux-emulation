/* This file is automatically generated.  DO NOT EDIT! */
/* Generated from: 	NetBSD: mknative-gcc,v 1.7 2003/08/22 00:24:46 mrg Exp  */

#define TARGET_CPU_DEFAULT (TARGET_CPU_DEFAULT_athlon_sse)
#ifndef NETBSD_ENABLE_PTHREADS
# define NETBSD_ENABLE_PTHREADS
#endif
#include "auto-build.h"
#ifdef IN_GCC
/* Provide three core typedefs used by everything, if we are compiling
   GCC.  These used to be found in rtl.h and tree.h, but this is no
   longer practical.  Providing these here rather that system.h allows
   the typedefs to be used everywhere within GCC. */
struct rtx_def;
typedef struct rtx_def *rtx;
struct rtvec_def;
typedef struct rtvec_def *rtvec;
union tree_node;
typedef union tree_node *tree;
#endif
#define GTY(x)
#ifdef IN_GCC
# include "ansidecl.h"
# include "i386/biarch64.h"
# include "i386/i386.h"
# include "i386/unix.h"
# include "i386/att.h"
# include "dbxelf.h"
# include "elfos.h"
# include "netbsd.h"
# include "netbsd-elf.h"
# include "i386/x86-64.h"
# include "i386/netbsd64.h"
# include "defaults.h"
#endif
#ifndef POSIX
# define POSIX
#endif
