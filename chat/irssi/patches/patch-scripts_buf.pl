$NetBSD: patch-scripts_buf.pl,v 1.1 2016/09/22 09:07:08 maya Exp $

Don't create a world readable file containing chat contents.
https://irssi.org/2016/09/22/buf.pl-update/

--- scripts/buf.pl.orig	2016-08-11 12:59:21.000000000 +0000
+++ scripts/buf.pl
@@ -5,7 +5,7 @@ use Irssi qw(command signal_add signal_a
              settings_get_str settings_get_bool channels windows
 	     settings_add_str settings_add_bool get_irssi_dir
 	     window_find_refnum signal_stop);
-$VERSION = '2.13';
+$VERSION = '2.20';
 %IRSSI = (
     authors	=> 'Juerd',
     contact	=> 'juerd@juerd.nl',
@@ -13,10 +13,8 @@ $VERSION = '2.13';
     description	=> 'Saves the buffer for /upgrade, so that no information is lost',
     license	=> 'Public Domain',
     url		=> 'http://juerd.nl/irssi/',
-    changed	=> 'Mon May 13 19:41 CET 2002',
-    changes	=> 'Severe formatting bug removed * oops, I ' .
-                   'exposed Irssi to ircII foolishness * sorry ' .
-		   '** removed logging stuff (this is a fix)',
+    changed	=> 'Thu Sep 22 01:37 CEST 2016',
+    changes	=> 'Fixed file permissions (leaked everything via filesystem)',
     note1	=> 'This script HAS TO BE in your scripts/autorun!',
     note2	=> 'Perl support must be static or in startup',
 );
@@ -39,9 +37,15 @@ use Data::Dumper;
 
 my %suppress;
 
+sub _filename { sprintf '%s/scrollbuffer', get_irssi_dir }
+
 sub upgrade {
-    open BUF, q{>}, sprintf('%s/scrollbuffer', get_irssi_dir) or die $!;
-    print BUF join("\0", map $_->{server}->{address} . $_->{name}, channels), "\n";
+    my $fn = _filename;
+    my $old_umask = umask 0077;
+    open my $fh, q{>}, $fn or die "open $fn: $!";
+    umask $old_umask;
+
+    print $fh join("\0", map $_->{server}->{address} . $_->{name}, channels), "\n";
     for my $window (windows) {
 	next unless defined $window;
 	next if $window->{name} eq 'status';
@@ -57,36 +61,39 @@ sub upgrade {
 		redo if defined $line;
 	    }
 	}
-	printf BUF "%s:%s\n%s", $window->{refnum}, $lines, $buf;
+	printf $fh "%s:%s\n%s", $window->{refnum}, $lines, $buf;
     }
-    close BUF;
+    close $fh;
     unlink sprintf("%s/sessionconfig", get_irssi_dir);
     command 'layout save';
     command 'save';
 }
 
 sub restore {
-    open BUF, q{<}, sprintf('%s/scrollbuffer', get_irssi_dir) or die $!;
-    my @suppress = split /\0/, <BUF>;
+    my $fn = _filename;
+    open my $fh, q{<}, $fn or die "open $fn: $!";
+    unlink $fn or warn "unlink $fn: $!";
+
+    my @suppress = split /\0/, readline $fh;
     if (settings_get_bool 'upgrade_suppress_join') {
 	chomp $suppress[-1];
 	@suppress{@suppress} = (2) x @suppress;
     }
     active_win->command('^window scroll off');
-    while (my $bla = <BUF>){
+    while (my $bla = readline $fh){
 	chomp $bla;
 	my ($refnum, $lines) = split /:/, $bla;
 	next unless $lines;
 	my $window = window_find_refnum $refnum;
 	unless (defined $window){
-	    <BUF> for 1..$lines;
+	    readline $fh for 1..$lines;
 	    next;
 	}
 	my $view = $window->view;
 	$view->remove_all_lines();
 	$view->redraw();
 	my $buf = '';
-	$buf .= <BUF> for 1..$lines;
+	$buf .= readline $fh for 1..$lines;
 	my $sep = settings_get_str 'upgrade_separator';
 	$sep .= "\n" if $sep ne '';
 	$window->gui_printtext_after(undef, MSGLEVEL_CLIENTNOTICE, "$buf\cO$sep");
@@ -119,3 +126,10 @@ signal_add       'event join'      => 's
 unless (-f sprintf('%s/scripts/autorun/buf.pl', get_irssi_dir)) {
     Irssi::print('PUT THIS SCRIPT IN ~/.irssi/scripts/autorun/ BEFORE /UPGRADING!!');
 }
+
+# Remove any left-over file. If 'session' doesn't exist (created by irssi
+# during /UPGRADE), neither should our file.
+unless (-e sprintf('%s/session', get_irssi_dir)) {
+    my $fn = _filename;
+    unlink $fn or warn "unlink $fn: $!" if -e $fn;
+}
