$NetBSD: patch-lily_pointer-group-interface.cc,v 1.1 2013/06/16 20:46:52 joerg Exp $

--- lily/pointer-group-interface.cc.orig	2013-06-16 19:23:13.000000000 +0000
+++ lily/pointer-group-interface.cc
@@ -17,6 +17,7 @@
   along with LilyPond.  If not, see <http://www.gnu.org/licenses/>.
 */
 
+#include "config.hh"
 #include "pointer-group-interface.hh"
 
 #include "grob-array.hh"
