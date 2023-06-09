<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

KIT INSTALLATION:

Unpack the kit into any convenient directory and run the BINDInstall
program.  This will install the named and associated programs into
the correct directories and set up the required registry keys.

Usually BINDInstall must be run by/as Administrator or it can fail
to operate on the filesystem or the registry or even return messages
like "A referral was returned from the server". The best way to
avoid this kind of problems on Windows 7 or newer is:
 - open a "Windows Explorer" window
 - go where the distribution was extracted
 - click right on the BINDInstall application
 - open "Properties" (last) menu
 - open "Compatibility" (second) tab
 - check the (last) "Run this program as an administrator" box
Unfortunately this is not saved by zip (or any archiver?) as
it is a property saved in the Registry.

BINDInstall requires that you install it under an account with
restricted privileges. The installer will prompt you for an account
name (the default is "named") and a password for that account. It
will also check for the existence of that account.  If it does not
exist is will create it with only the privileges required to run
BIND 9. If the account does exist it will check that it has only the
one privilege required: "Log on as a service".  If it has too many
privileges it will prompt you if you want to continue.

With BIND 9 running under an account name, it is necessary for all
files and directories that BIND 9 uses to have permissions set up for
the named account if the files are on an NTFS disk. BIND 9 requires
that the account have read and write access to the directory for
the pid file, any files that are maintained either for slave zones
or for master zones supporting dynamic updates. The account will
also need read access to the named.conf and any other file that it
needs to read.

"NT AUTHORITY\LocalService" is also an acceptable account
(and the only acceptable on some recent versions of Windows).
This account is built into Windows and no password is required.
Appropriate file permissions will also need to be set for "NT
AUTHORITY\LocalService" similar to those that would have been
required for the "named" account.

It is important that on Windows the directory directive is used in
the options section to tell BIND 9 where to find the files used in
named.conf (default "%ProgramFiles%\ISC BIND 9\etc\named.conf"). For
example:

	options {
		directory "C:\Program Files (x86)\ISC BIND 9\etc";
	};

for a 32 bit BIND 9 on a 64 bit US Domestic Windows system.
Messages are logged to the Application log in the EventViewer.

CONTROLLING BIND 9:

Windows uses the same rndc program as is used on Unix systems.  The
rndc.conf file must be configured for your system in order to work.
You will need to generate a key for this. To do this use the
rndc-confgen program. The program will be installed in the same
directory as named: "%ProgramFiles%\ISC BIND 9\bin".  From the DOS
prompt, use the command this way:

rndc-confgen -a

which will create a rndc.key file in the "%ProgramFiles%\ISC BIND 9\etc"
directory. This will allow you to run rndc without an explicit
rndc.conf file or key and control entry in named.conf file. See
the ARM for details of this. An rndc.conf can also be generated by
running:

rndc-confgen > rndc.conf

which will create the rndc.conf file in the current directory, but
not copy it to the "%ProgramFiles%\ISC BIND 9\etc" directory where
it needs to reside. If you create rndc.conf this way you will need
to copy the same key statement into named.conf.

The additions look like the following:

key "rndc-key" { algorithm hmac-sha256; secret "xxxxxxxxx=="; };

controls {
	inet 127.0.0.1 port 953 allow { localhost; } keys { "rndc-key"; };
};

Note that the value of the secret must come from the key generated
above for rndc and must be the same key value for both. Details of
this may be found in the ARM. If you have rndc on a Unix box you can
use it to control BIND 9 on the Windows box as well as using the Windows
version of rndc to control a BIND 9 daemon on a Unix box. However you
must have key statements valid for the servers you wish to control,
specifically the IP address and key in both named.conf and rndc.conf.
Again see the ARM for details.

In order to run rndc from a different system it is important to
ensure that the clocks are synchronized. The clocks must be kept
within 5 minutes of each other or the rndc commands will fail
authentication. Use NTP or other time synchronization software to
keep your clocks accurate. NTP can be found at http://www.ntp.org/.

In addition BIND 9 is installed as a win32 system service, can be
started and stopped in the same way as any other service and
automatically starts whenever the system is booted. Signals are not
supported and are in fact ignored.

Note: Unlike most Windows applications, named does not change its
working directory when started as a service.  If you wish to use
relative files in named.conf you will need to specify a working
directory using the directory directive options.

DOCUMENTATION:

This kit includes Documentation in HTML format.  The documentation
is not copied during the installation process so you should move
it to any convenient location for later reference. Of particular
importance is the BIND 9 Administrator's Reference Manual (Bv9ARM*.html)
which provides detailed information on BIND 9. In addition, there
are HTML pages for each of the BIND 9 applications.

IMPORTANT NOTE ON USING BIND 9 TOOLS:

It is no longer necessary to create a resolv.conf file on Windows
as BIND 9 tools will look in the registry for the required name server
information. However, if you do create a resolv.conf file as follows,
the tools will use it in preference to the registry name server
entries.

Place resolv.conf the "%ProgramFiles%\ISC BIND 9\etc" directory.
It must contain a list of recursive server addresses.  The format
of this file is:

nameserver 1.2.3.4
nameserver 5.6.7.8

Replace the above IP addresses with the real name server addresses.
127.0.0.1 is a valid address if you are running a recursive name
server on the localhost.

PROBLEMS:

Please report bugs at https://gitlab.isc.org/isc-projects/bind9.
Other questions can go to the bind-users@isc.org mailing list.
