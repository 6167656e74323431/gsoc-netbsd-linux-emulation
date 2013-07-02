$NetBSD: patch-imakemdep.h,v 1.2 2013/07/02 12:12:48 joerg Exp $

--- imakemdep.h.orig	2012-03-08 05:47:32.000000000 +0000
+++ imakemdep.h
@@ -265,87 +265,7 @@ in this Software without prior written a
  *     If the cpp you need is not in /lib/cpp, define DEFAULT_CPP.
  */
 #  if !defined (CROSSCOMPILE) || defined (CROSSCOMPILE_CPP)
-
-#   if defined(__APPLE__)
-#    define DEFAULT_CPP "/usr/bin/cpp"
-#    define DEFAULT_CC "cc"
-#   endif
-#   if defined(Lynx) || defined(__Lynx__)
-#    define DEFAULT_CC "gcc"
-#    define USE_CC_E
-#   endif
-#   ifdef hpux
-#    define USE_CC_E
-#   endif
-#   ifdef WIN32
-#    define USE_CC_E
-#    ifdef __GNUC__
-#     define DEFAULT_CC "gcc"
-#    else
-#     define DEFAULT_CC "cl"
-#    endif
-#   endif
-#   ifdef apollo
-#    define DEFAULT_CPP "/usr/lib/cpp"
-#   endif
-#   if defined(clipper) || defined(__clipper__)
-#    define DEFAULT_CPP "/usr/lib/cpp"
-#   endif
-#   if defined(_IBMR2) && !defined(DEFAULT_CPP)
-#    define DEFAULT_CPP "/usr/ccs/lib/cpp"
-#   endif
-#   if defined(sun) && (defined(SVR4) || defined(__svr4__) || defined(__SVR4) || defined(__sol__))
-#    define DEFAULT_CPP "/usr/ccs/lib/cpp"
-#   endif
-#   ifdef __bsdi__
-#    define DEFAULT_CPP "/usr/bin/cpp"
-#   endif
-#   ifdef __uxp__
-#    define DEFAULT_CPP "/usr/ccs/lib/cpp"
-#   endif
-#   ifdef __sxg__
-#    define DEFAULT_CPP "/usr/lib/cpp"
-#   endif
-#   ifdef _CRAY
-#    define DEFAULT_CPP "/lib/pcpp"
-#   endif
-#   if defined(__386BSD__)
-#    define DEFAULT_CPP "/usr/libexec/cpp"
-#   endif
-#   if defined(__FreeBSD__)  || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
-#    define USE_CC_E
-#   endif
-#   if defined(__sgi) && defined(__ANSI_CPP__)
-#    define USE_CC_E
-#   endif
-#   if defined(MACH) && !defined(__GNU__)
-#    define USE_CC_E
-#   endif
-#   ifdef __minix_vmd
-#    define DEFAULT_CPP "/usr/lib/cpp"
-#   endif
-#   if defined(__UNIXOS2__)
-/* expects cpp in PATH */
-#    define DEFAULT_CPP "cpp"
-#   endif
-#   ifdef __CYGWIN__
-#    define DEFAULT_CC "gcc"
-#    define DEFAULT_CPP "/usr/bin/cpp"
-#   endif
-#   if defined (__QNX__)
-#    ifdef __QNXNTO__
-#     define DEFAULT_CPP "/usr/bin/cpp"
-#    else
-#     define DEFAULT_CPP "/usr/X11R6/bin/cpp"
-#    endif
-#   endif
-#   if defined(__GNUC__) && !defined(USE_CC_E)
-#    define USE_CC_E
-#    ifndef DEFAULT_CC
-#     define DEFAULT_CC "gcc"
-#    endif
-#   endif
-
+#    define DEFAULT_CPP RAWCPP
 #  endif /* !defined (CROSSCOMPILE) || defined (CROSSCOMPILE_CPP) */
 /*
  * Step 5:  cpp_argv
@@ -367,7 +287,7 @@ in this Software without prior written a
 #  define	ARGUMENTS 50	/* number of arguments in various arrays */
 #  if !defined (CROSSCOMPILE) || defined (CROSSCOMPILE_CPP)
 const char *cpp_argv[ARGUMENTS] = {
-	"cc",		/* replaced by the actual program to exec */
+	"cpp",		/* replaced by the actual program to exec */
 	"-I.",		/* add current directory to include path */
 #   if !defined(__NetBSD_Version__) || __NetBSD_Version__ < 103080000
 #    ifdef unix
