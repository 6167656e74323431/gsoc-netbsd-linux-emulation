/* -*-C++-*-	$NetBSD: arch.cpp,v 1.1 2001/02/09 18:34:33 uch Exp $	 */

/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by UCHIYAMA Yasushi.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <hpcboot.h>
#include <hpcmenu.h>

#include <console.h>
#include <memory.h>
#include <load.h>
#include <arch.h>
#include <framebuffer.h>

Architecture::Architecture(Console *&cons, MemoryManager *&mem)
	:_cons(cons), _mem(mem)
{
	_loader_addr = 0;
	_debug = FALSE;
	_dll = 0;
}

Architecture::~Architecture(void)
{
	if (_dll)
		FreeLibrary(_dll);
}

BOOL
Architecture::allocateMemory(size_t sz)
{
	//binary image.
	sz = _mem->estimateTaggedPageSize(sz);
	//pvec + BootArgs + 2 nd bootloader + bootloader stack.
	sz += _mem->getPageSize() * 4;
	sz = _mem->roundRegion(sz);
	return _mem->reservePage(sz);
}

paddr_t
Architecture::setupBootInfo(Loader & loader)
{
	HpcMenuInterface &menu = HpcMenuInterface::Instance();
	vaddr_t v;
	paddr_t p;

	_mem->getPage(v, p);

	struct BootArgs *karg = reinterpret_cast < struct BootArgs *>(v);

	karg->argc = menu.setup_kernel_args(v + sizeof(struct BootArgs),
					    p + sizeof(struct BootArgs));
	karg->argv = ptokv(p + sizeof(struct BootArgs));
	menu.setup_bootinfo(karg->bi);
	karg->bootinfo = ptokv(p + offsetof(struct BootArgs, bi));
	karg->kernel_entry = loader.jumpAddr();

	DPRINTF((TEXT("frame buffer: %dx%d type=%d linebytes=%d addr=0x%08x\n"),
		 karg->bi.fb_width, karg->bi.fb_height, karg->bi.fb_type,
		 karg->bi.fb_line_bytes, karg->bi.fb_addr));

	return p;
}

void *
Architecture::_load_func(const TCHAR * name)
{
	if (_dll == 0)
		_dll = LoadLibrary(TEXT("coredll.dll"));

	return _dll
		? reinterpret_cast <void *>(GetProcAddress(_dll, name))
		: 0;
}

void
Architecture::systemInfo(void)
{
	int(*func)(HDC, int, int, LPCSTR, int, LPSTR);
	u_int32_t val = 0;
	int ret;
	HDC hdc;

	// inquire default setting.
	FrameBufferInfo fb(0, 0);
	DPRINTF((TEXT("[DISPLAY] %dx%d %dbpp\n"), fb.width(), fb.height(),
		 fb.bpp()));

	func = reinterpret_cast <int(*)(HDC, int, int, LPCSTR, int, LPSTR)>
		(_load_func(TEXT("ExtEscape")));
	if (func == 0) {
		DPRINTF((TEXT("ExtEscape not found.\n")));
		return;
	}
	hdc = GetDC(0);
	ret = func(hdc, GETVFRAMEPHYSICAL, 0, 0, sizeof(u_int32_t),
		   reinterpret_cast <char *>(&val));
	if (ret == 0)
		DPRINTF((TEXT("ExtEscape(GETVFRAMEPHYSICAL) not implemented.\n")));
	else if (ret < 0)
		DPRINTF((TEXT("ExtEscape(GETVFRAMEPHYSICAL) failure.\n")));
	else
		DPRINTF((TEXT("frame buffer physical address: 0x%08x\n"),
			 val));

	ret = func(hdc, GETVFRAMELEN, 0, 0, sizeof(u_int32_t),
		   reinterpret_cast <char *>(&val));

	if (ret == 0)
		DPRINTF((TEXT("ExtEscape(GETVFRAMELEN) not implemented.\n")));
	else if (ret < 0)
		DPRINTF((TEXT("ExtEscape(GETVFRAMELEN) failure.\n")));
	else
		DPRINTF((TEXT("frame buffer length: 0x%08x\n"), val));

	ReleaseDC(0, hdc);

}

BOOL(*Architecture::_load_LockPages(void))(LPVOID, DWORD, PDWORD, int)
{
	return reinterpret_cast <BOOL(*)(LPVOID, DWORD, PDWORD, int)>
		(_load_func(TEXT("LockPages")));
}

BOOL(*Architecture::_load_UnlockPages(void))(LPVOID, DWORD)
{
	return reinterpret_cast <BOOL(*)(LPVOID, DWORD)>
		(_load_func(TEXT("UnlockPages")));
}

//
// Debug support.
//
void
Architecture::_bitdisp(u_int32_t a, int s, int e, int m, int c)
{
	u_int32_t j, j1;
	int i, n;

	n = 31;	// 32bit only.
	j1 = 1 << n;
	e = e ? e : n;
	for (j = j1, i = n; j > 0; j >>=1, i--) {
		if (i > e || i < s) {
			DPRINTF((TEXT("%c"), a & j ? '+' : '-'));
		} else {
			DPRINTF((TEXT("%c"), a & j ? '|' : '.'));
		}
	}
	if (m) {
		DPRINTF((TEXT("[%s]"),(char*)m));
	}
	if (c) {
		for (j = j1, i = n; j > 0; j >>=1, i--) {
			if (!(i > e || i < s) &&(a & j)) {
				DPRINTF((TEXT(" %d"), i));
			}
		}
	}
	DPRINTF((TEXT(" [0x%08x] %d"), a, a));
	DPRINTF((TEXT("\n")));
}

void
Architecture::_dbg_bit_print(u_int32_t reg, u_int32_t mask, const char *name)
{
	static const char onoff[3] = "_x";
	DPRINTF((TEXT("%S[%c] "), name, onoff[reg & mask ? 1 : 0]));
}
