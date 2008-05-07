/*	$NetBSD: ieee80211.h,v 1.7 2008/05/07 19:55:24 dyoung Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "parse.h"

extern struct pinteger parse_chan, parse_frag;
extern struct pkw kw80211;
extern struct pkw ieee80211bool;
extern struct pstr parse_bssid, parse_ssid, parse_nwkey;
extern struct pinteger parse_powersavesleep;

int	sethidessid(prop_dictionary_t, prop_dictionary_t);
int	setapbridge(prop_dictionary_t, prop_dictionary_t);
int	setifssid(prop_dictionary_t, prop_dictionary_t);
int	setifnwkey(prop_dictionary_t, prop_dictionary_t);
int	unsetifnwkey(prop_dictionary_t, prop_dictionary_t);
int	unsetifbssid(prop_dictionary_t, prop_dictionary_t);
int	setifbssid(prop_dictionary_t, prop_dictionary_t);
int	setifchan(prop_dictionary_t, prop_dictionary_t);
int	setiffrag(prop_dictionary_t, prop_dictionary_t);
int	setifpowersave(prop_dictionary_t, prop_dictionary_t);
int	setifpowersavesleep(prop_dictionary_t, prop_dictionary_t);
int	scan_exec(prop_dictionary_t, prop_dictionary_t);

void	ieee80211_statistics(prop_dictionary_t);
void	ieee80211_status(prop_dictionary_t, prop_dictionary_t);
