#objdump: -dr --prefix-addresses --show-raw-insn -mmips:sb1 -M gpr-names=32
#name: .set arch=FOO
#stderr: set-arch.l

dump\.o:     file format .*mips

Disassembly of section \.text:
00000000 <[^>]*> bc010000 	cache	0x1,0\(zero\)
00000004 <[^>]*> bc020000 	cache	0x2,0\(zero\)
00000008 <[^>]*> bc030000 	cache	0x3,0\(zero\)
0000000c <[^>]*> 0085001c 	dmult	a0,a1
00000010 <[^>]*> 00a6001d 	dmultu	a1,a2
00000014 <[^>]*> 00e0300b 	movn	a2,a3,zero
00000018 <[^>]*> 0100380a 	movz	a3,t0,zero
0000001c <[^>]*> 0109001e 	ddiv	zero,t0,t1
00000020 <[^>]*> 012a001f 	ddivu	zero,t1,t2
00000024 <[^>]*> 016c5005 	0x16c5005
00000028 <[^>]*> 018d5801 	movt	t3,t4,\$fcc3
0000002c <[^>]*> 42000020 	wait
00000030 <[^>]*> bdc40010 	cache	0x4,16\(t6\)
00000034 <[^>]*> 71ee0010 	0x71ee0010
00000038 <[^>]*> 42000023 	c0	0x23
0000003c <[^>]*> 42000021 	c0	0x21
00000040 <[^>]*> 42000022 	c0	0x22
00000044 <[^>]*> 70850000 	madd	a0,a1
00000048 <[^>]*> 70a60001 	maddu	a1,a2
0000004c <[^>]*> 70e83002 	mul	a2,a3,t0
00000050 <[^>]*> 4500ffff 	bc1f	00000050 <[^>]*>
00000054 <[^>]*> 4504fffe 	bc1f	\$fcc1,00000050 <[^>]*>
00000058 <[^>]*> 4506fffd 	bc1fl	\$fcc1,00000050 <[^>]*>
0000005c <[^>]*> 4505fffc 	bc1t	\$fcc1,00000050 <[^>]*>
00000060 <[^>]*> 450bfffb 	bc1tl	\$fcc2,00000050 <[^>]*>
00000064 <[^>]*> 46262030 	c\.f\.d	\$f4,\$f6
00000068 <[^>]*> 46262130 	c\.f\.d	\$fcc1,\$f4,\$f6
0000006c <[^>]*> 4ca40081 	ldxc1	\$f2,a0\(a1\)
00000070 <[^>]*> 4ca40080 	lwxc1	\$f2,a0\(a1\)
00000074 <[^>]*> 4c462021 	madd\.d	\$f0,\$f2,\$f4,\$f6
00000078 <[^>]*> 4c462020 	madd\.s	\$f0,\$f2,\$f4,\$f6
0000007c <[^>]*> 00b02001 	movf	a0,a1,\$fcc4
00000080 <[^>]*> 46203111 	movf\.d	\$f4,\$f6,\$fcc0
00000084 <[^>]*> 46003111 	movf\.s	\$f4,\$f6,\$fcc0
00000088 <[^>]*> 00c6200b 	movn	a0,a2,a2
0000008c <[^>]*> 46263113 	movn\.d	\$f4,\$f6,a2
00000090 <[^>]*> 46063113 	movn\.s	\$f4,\$f6,a2
00000094 <[^>]*> 00b12001 	movt	a0,a1,\$fcc4
00000098 <[^>]*> 46213111 	movt\.d	\$f4,\$f6,\$fcc0
0000009c <[^>]*> 46013111 	movt\.s	\$f4,\$f6,\$fcc0
000000a0 <[^>]*> 00c6200a 	movz	a0,a2,a2
000000a4 <[^>]*> 46263112 	movz\.d	\$f4,\$f6,a2
000000a8 <[^>]*> 46063112 	movz\.s	\$f4,\$f6,a2
000000ac <[^>]*> 4c462029 	msub\.d	\$f0,\$f2,\$f4,\$f6
000000b0 <[^>]*> 4c462028 	msub\.s	\$f0,\$f2,\$f4,\$f6
000000b4 <[^>]*> 4c462031 	nmadd\.d	\$f0,\$f2,\$f4,\$f6
000000b8 <[^>]*> 4c462030 	nmadd\.s	\$f0,\$f2,\$f4,\$f6
000000bc <[^>]*> 4c462039 	nmsub\.d	\$f0,\$f2,\$f4,\$f6
000000c0 <[^>]*> 4c462038 	nmsub\.s	\$f0,\$f2,\$f4,\$f6
000000c4 <[^>]*> 4ca4200f 	prefx	0x4,a0\(a1\)
000000c8 <[^>]*> 46203115 	recip\.d	\$f4,\$f6
000000cc <[^>]*> 46003115 	recip\.s	\$f4,\$f6
000000d0 <[^>]*> 46203116 	rsqrt\.d	\$f4,\$f6
000000d4 <[^>]*> 46003116 	rsqrt\.s	\$f4,\$f6
000000d8 <[^>]*> 4ca42009 	sdxc1	\$f4,a0\(a1\)
000000dc <[^>]*> 4ca42008 	swxc1	\$f4,a0\(a1\)
000000e0 <[^>]*> 46c01005 	abs\.ps	\$f0,\$f2
000000e4 <[^>]*> 46c62080 	add\.ps	\$f2,\$f4,\$f6
000000e8 <[^>]*> 4c6a419e 	alnv\.ps	\$f6,\$f8,\$f10,v1
000000ec <[^>]*> 46ca4032 	c\.eq\.ps	\$f8,\$f10
000000f0 <[^>]*> 46cc5232 	c\.eq\.ps	\$fcc2,\$f10,\$f12
000000f4 <[^>]*> 46ca4030 	c\.f\.ps	\$f8,\$f10
000000f8 <[^>]*> 46cc5230 	c\.f\.ps	\$fcc2,\$f10,\$f12
000000fc <[^>]*> 46ca403e 	c\.le\.ps	\$f8,\$f10
00000100 <[^>]*> 46cc523e 	c\.le\.ps	\$fcc2,\$f10,\$f12
00000104 <[^>]*> 46ca403c 	c\.lt\.ps	\$f8,\$f10
00000108 <[^>]*> 46cc523c 	c\.lt\.ps	\$fcc2,\$f10,\$f12
0000010c <[^>]*> 46ca403d 	c\.nge\.ps	\$f8,\$f10
00000110 <[^>]*> 46cc523d 	c\.nge\.ps	\$fcc2,\$f10,\$f12
00000114 <[^>]*> 46ca403b 	c\.ngl\.ps	\$f8,\$f10
00000118 <[^>]*> 46cc523b 	c\.ngl\.ps	\$fcc2,\$f10,\$f12
0000011c <[^>]*> 46ca4039 	c\.ngle\.ps	\$f8,\$f10
00000120 <[^>]*> 46cc5239 	c\.ngle\.ps	\$fcc2,\$f10,\$f12
00000124 <[^>]*> 46ca403f 	c\.ngt\.ps	\$f8,\$f10
00000128 <[^>]*> 46cc523f 	c\.ngt\.ps	\$fcc2,\$f10,\$f12
0000012c <[^>]*> 46ca4036 	c\.ole\.ps	\$f8,\$f10
00000130 <[^>]*> 46cc5236 	c\.ole\.ps	\$fcc2,\$f10,\$f12
00000134 <[^>]*> 46ca4034 	c\.olt\.ps	\$f8,\$f10
00000138 <[^>]*> 46cc5234 	c\.olt\.ps	\$fcc2,\$f10,\$f12
0000013c <[^>]*> 46ca403a 	c\.seq\.ps	\$f8,\$f10
00000140 <[^>]*> 46cc523a 	c\.seq\.ps	\$fcc2,\$f10,\$f12
00000144 <[^>]*> 46ca4038 	c\.sf\.ps	\$f8,\$f10
00000148 <[^>]*> 46cc5238 	c\.sf\.ps	\$fcc2,\$f10,\$f12
0000014c <[^>]*> 46ca4033 	c\.ueq\.ps	\$f8,\$f10
00000150 <[^>]*> 46cc5233 	c\.ueq\.ps	\$fcc2,\$f10,\$f12
00000154 <[^>]*> 46ca4037 	c\.ule\.ps	\$f8,\$f10
00000158 <[^>]*> 46cc5237 	c\.ule\.ps	\$fcc2,\$f10,\$f12
0000015c <[^>]*> 46ca4035 	c\.ult\.ps	\$f8,\$f10
00000160 <[^>]*> 46cc5235 	c\.ult\.ps	\$fcc2,\$f10,\$f12
00000164 <[^>]*> 46ca4031 	c\.un\.ps	\$f8,\$f10
00000168 <[^>]*> 46cc5231 	c\.un\.ps	\$fcc2,\$f10,\$f12
0000016c <[^>]*> 46107326 	cvt\.ps\.s	\$f12,\$f14,\$f16
00000170 <[^>]*> 46c09428 	cvt\.s\.pl	\$f16,\$f18
00000174 <[^>]*> 46c0a4a0 	cvt\.s\.pu	\$f18,\$f20
00000178 <[^>]*> 4ca40505 	luxc1	\$f20,a0\(a1\)
0000017c <[^>]*> 4edac526 	madd\.ps	\$f20,\$f22,\$f24,\$f26
00000180 <[^>]*> 46c0d606 	mov\.ps	\$f24,\$f26
00000184 <[^>]*> 46c8e691 	movf\.ps	\$f26,\$f28,\$fcc2
00000188 <[^>]*> 46c3e693 	movn\.ps	\$f26,\$f28,v1
0000018c <[^>]*> 46d1f711 	movt\.ps	\$f28,\$f30,\$fcc4
00000190 <[^>]*> 46c5f712 	movz\.ps	\$f28,\$f30,a1
00000194 <[^>]*> 4c0417ae 	msub\.ps	\$f30,\$f0,\$f2,\$f4
00000198 <[^>]*> 46c62082 	mul\.ps	\$f2,\$f4,\$f6
0000019c <[^>]*> 46c04187 	neg\.ps	\$f6,\$f8
000001a0 <[^>]*> 4d0c51b6 	nmadd\.ps	\$f6,\$f8,\$f10,\$f12
000001a4 <[^>]*> 4d0c51be 	nmsub\.ps	\$f6,\$f8,\$f10,\$f12
000001a8 <[^>]*> 46ce62ac 	pll\.ps	\$f10,\$f12,\$f14
000001ac <[^>]*> 46d283ad 	plu\.ps	\$f14,\$f16,\$f18
000001b0 <[^>]*> 46d4942e 	pul\.ps	\$f16,\$f18,\$f20
000001b4 <[^>]*> 46d8b52f 	puu\.ps	\$f20,\$f22,\$f24
000001b8 <[^>]*> 46dac581 	sub\.ps	\$f22,\$f24,\$f26
000001bc <[^>]*> 4ce6d00d 	suxc1	\$f26,a2\(a3\)
000001c0 <[^>]*> 46cc5332 	c\.eq\.ps	\$fcc3,\$f10,\$f12
000001c4 <[^>]*> 46cce691 	movf\.ps	\$f26,\$f28,\$fcc3
000001c8 <[^>]*> 70410821 	clo	at,v0
000001cc <[^>]*> 70831820 	clz	v1,a0
000001d0 <[^>]*> 70a60000 	madd	a1,a2
000001d4 <[^>]*> 70e80001 	maddu	a3,t0
000001d8 <[^>]*> 712a0004 	msub	t1,t2
000001dc <[^>]*> 716c0005 	msubu	t3,t4
000001e0 <[^>]*> 71cf6802 	mul	t5,t6,t7
000001e4 <[^>]*> ce040000 	pref	0x4,0\(s0\)
000001e8 <[^>]*> ce247fff 	pref	0x4,32767\(s1\)
000001ec <[^>]*> ce448000 	pref	0x4,-32768\(s2\)
000001f0 <[^>]*> 00000040 	ssnop
000001f4 <[^>]*> 4900ff96 	bc2f	00000050 <[^>]*>
000001f8 <[^>]*> 00000000 	nop
000001fc <[^>]*> 4902ff94 	bc2fl	00000050 <[^>]*>
00000200 <[^>]*> 00000000 	nop
00000204 <[^>]*> 4901ff92 	bc2t	00000050 <[^>]*>
00000208 <[^>]*> 00000000 	nop
0000020c <[^>]*> 4903ff90 	bc2tl	00000050 <[^>]*>
00000210 <[^>]*> 00000000 	nop
00000214 <[^>]*> 48411000 	cfc2	at,\$2
00000218 <[^>]*> 4b234567 	c2	0x1234567
0000021c <[^>]*> 48c21800 	ctc2	v0,\$3
00000220 <[^>]*> 48032000 	mfc2	v1,\$4
00000224 <[^>]*> 48042800 	mfc2	a0,\$5
00000228 <[^>]*> 48053007 	mfc2	a1,\$6,7
0000022c <[^>]*> 48863800 	mtc2	a2,\$7
00000230 <[^>]*> 48874000 	mtc2	a3,\$8
00000234 <[^>]*> 48884807 	mtc2	t0,\$9,7
00000238 <[^>]*> bc250000 	cache	0x5,0\(at\)
0000023c <[^>]*> bc457fff 	cache	0x5,32767\(v0\)
00000240 <[^>]*> bc658000 	cache	0x5,-32768\(v1\)
00000244 <[^>]*> 42000018 	eret
00000248 <[^>]*> 42000008 	tlbp
0000024c <[^>]*> 42000001 	tlbr
00000250 <[^>]*> 42000002 	tlbwi
00000254 <[^>]*> 42000006 	tlbwr
00000258 <[^>]*> 42000020 	wait
0000025c <[^>]*> 42000020 	wait
00000260 <[^>]*> 4359e260 	wait	0x56789
00000264 <[^>]*> 0000000d 	break
00000268 <[^>]*> 0000000d 	break
0000026c <[^>]*> 0345000d 	break	0x345
00000270 <[^>]*> 0048d14d 	break	0x48,0x345
00000274 <[^>]*> 7000003f 	sdbbp
00000278 <[^>]*> 7000003f 	sdbbp
0000027c <[^>]*> 7159e27f 	sdbbp	0x56789
00000280 <[^>]*> 000000c0 	sll	zero,zero,0x3
00000284 <[^>]*> 7ca43980 	0x7ca43980
00000288 <[^>]*> 7ca46984 	0x7ca46984
0000028c <[^>]*> 0100fc09 	0x100fc09
00000290 <[^>]*> 0120a409 	0x120a409
00000294 <[^>]*> 01000408 	0x1000408
00000298 <[^>]*> 7c0a003b 	0x7c0a003b
0000029c <[^>]*> 7c0b083b 	0x7c0b083b
000002a0 <[^>]*> 7c0c103b 	0x7c0c103b
000002a4 <[^>]*> 7c0d183b 	0x7c0d183b
000002a8 <[^>]*> 7c0e203b 	0x7c0e203b
000002ac <[^>]*> 7c0f283b 	0x7c0f283b
000002b0 <[^>]*> 002acf02 	0x2acf02
000002b4 <[^>]*> 002ac902 	0x2ac902
000002b8 <[^>]*> 0004c823 	negu	t9,a0
000002bc <[^>]*> 032ac846 	0x32ac846
000002c0 <[^>]*> 008ac846 	0x8ac846
000002c4 <[^>]*> 008ac846 	0x8ac846
000002c8 <[^>]*> 7c073c20 	0x7c073c20
000002cc <[^>]*> 7c0a4420 	0x7c0a4420
000002d0 <[^>]*> 7c073e20 	0x7c073e20
000002d4 <[^>]*> 7c0a4620 	0x7c0a4620
000002d8 <[^>]*> 055f5555 	0x55f5555
000002dc <[^>]*> 7c0738a0 	0x7c0738a0
000002e0 <[^>]*> 7c0a40a0 	0x7c0a40a0
000002e4 <[^>]*> 41606000 	0x41606000
000002e8 <[^>]*> 41606000 	0x41606000
000002ec <[^>]*> 416a6000 	0x416a6000
000002f0 <[^>]*> 41606020 	0x41606020
000002f4 <[^>]*> 41606020 	0x41606020
000002f8 <[^>]*> 416a6020 	0x416a6020
000002fc <[^>]*> 41595000 	0x41595000
00000300 <[^>]*> 41d95000 	0x41d95000
00000304 <[^>]*> 44710000 	0x44710000
00000308 <[^>]*> 44f10000 	0x44f10000
0000030c <[^>]*> 48715555 	0x48715555
00000310 <[^>]*> 48f15555 	0x48f15555
00000314 <[^>]*> 70410825 	dclo	at,v0
00000318 <[^>]*> 70831824 	dclz	v1,a0
0000031c <[^>]*> 48232000 	dmfc2	v1,\$4
00000320 <[^>]*> 48242800 	dmfc2	a0,\$5
00000324 <[^>]*> 48253007 	dmfc2	a1,\$6,7
00000328 <[^>]*> 48a63800 	dmtc2	a2,\$7
0000032c <[^>]*> 48a74000 	dmtc2	a3,\$8
00000330 <[^>]*> 48a84807 	dmtc2	t0,\$9,7
00000334 <[^>]*> 00850029 	0x850029
00000338 <[^>]*> 00a60028 	0xa60028
0000033c <[^>]*> 00002012 	mflo	a0
00000340 <[^>]*> 00a62029 	0xa62029
00000344 <[^>]*> 00a62229 	0xa62229
00000348 <[^>]*> 00a62629 	0xa62629
0000034c <[^>]*> 00a62269 	0xa62269
00000350 <[^>]*> 00a62669 	0xa62669
00000354 <[^>]*> 00a62429 	0xa62429
00000358 <[^>]*> 00a62069 	0xa62069
0000035c <[^>]*> 00a62469 	0xa62469
00000360 <[^>]*> 00002012 	mflo	a0
00000364 <[^>]*> 00a62028 	0xa62028
00000368 <[^>]*> 00a62228 	0xa62228
0000036c <[^>]*> 00a62628 	0xa62628
00000370 <[^>]*> 00a62268 	0xa62268
00000374 <[^>]*> 00a62668 	0xa62668
00000378 <[^>]*> 00a62428 	0xa62428
0000037c <[^>]*> 00a62068 	0xa62068
00000380 <[^>]*> 00a62468 	0xa62468
00000384 <[^>]*> 00a62059 	0xa62059
00000388 <[^>]*> 00a62258 	0xa62258
0000038c <[^>]*> 00a62259 	0xa62259
00000390 <[^>]*> 00a620d8 	0xa620d8
00000394 <[^>]*> 00a620d9 	0xa620d9
00000398 <[^>]*> 00a622d8 	0xa622d8
0000039c <[^>]*> 00a622d9 	0xa622d9
000003a0 <[^>]*> 00a62158 	0xa62158
000003a4 <[^>]*> 00a62159 	0xa62159
000003a8 <[^>]*> 00a62358 	0xa62358
000003ac <[^>]*> 00a62359 	0xa62359
000003b0 <[^>]*> 00a621d8 	0xa621d8
000003b4 <[^>]*> 00a621d9 	0xa621d9
000003b8 <[^>]*> 00a623d8 	0xa623d8
000003bc <[^>]*> 00a623d9 	0xa623d9
000003c0 <[^>]*> 00252642 	0x252642
000003c4 <[^>]*> 00c52046 	0xc52046
000003c8 <[^>]*> 0025267a 	0x25267a
000003cc <[^>]*> 0025267e 	0x25267e
000003d0 <[^>]*> 0025267e 	0x25267e
000003d4 <[^>]*> 00c52056 	0xc52056
000003d8 <[^>]*> 7000003f 	sdbbp
000003dc <[^>]*> 7000003e 	0x7000003e
000003e0 <[^>]*> 7003183d 	0x7003183d
000003e4 <[^>]*> 7083183d 	0x7083183d
000003e8 <[^>]*> 4004c803 	mfc0	a0,c0_perfcnt,3
000003ec <[^>]*> 4004c802 	mfc0	a0,c0_perfcnt,2
000003f0 <[^>]*> 4084c803 	mtc0	a0,c0_perfcnt,3
000003f4 <[^>]*> 4084c802 	mtc0	a0,c0_perfcnt,2
000003f8 <[^>]*> 4ac4100b 	c2	0xc4100b
000003fc <[^>]*> 4886208b 	0x4886208b
00000400 <[^>]*> 4bcf218b 	c2	0x1cf218b
00000404 <[^>]*> 4bdf310b 	c2	0x1df310b
00000408 <[^>]*> 4ac4100c 	c2	0xc4100c
0000040c <[^>]*> 4886208c 	0x4886208c
00000410 <[^>]*> 4bcf218c 	c2	0x1cf218c
00000414 <[^>]*> 4bdf310c 	c2	0x1df310c
00000418 <[^>]*> 4ac20001 	c2	0xc20001
0000041c <[^>]*> 48862001 	mtc2	a2,\$4,1
00000420 <[^>]*> 4bcf3001 	c2	0x1cf3001
00000424 <[^>]*> 4bdf2001 	c2	0x1df2001
00000428 <[^>]*> 4ac20005 	c2	0xc20005
0000042c <[^>]*> 48862005 	mtc2	a2,\$4,5
00000430 <[^>]*> 4bcf3005 	c2	0x1cf3005
00000434 <[^>]*> 4bdf2005 	c2	0x1df2005
00000438 <[^>]*> 4ac20004 	c2	0xc20004
0000043c <[^>]*> 48862004 	mtc2	a2,\$4,4
00000440 <[^>]*> 4bcf3004 	c2	0x1cf3004
00000444 <[^>]*> 4bdf2004 	c2	0x1df2004
00000448 <[^>]*> 4ac41007 	c2	0xc41007
0000044c <[^>]*> 48862087 	0x48862087
00000450 <[^>]*> 4bcf2187 	c2	0x1cf2187
00000454 <[^>]*> 4bdf3107 	c2	0x1df3107
00000458 <[^>]*> 4ac41006 	c2	0xc41006
0000045c <[^>]*> 48862086 	0x48862086
00000460 <[^>]*> 4bcf2186 	c2	0x1cf2186
00000464 <[^>]*> 4bdf3106 	c2	0x1df3106
00000468 <[^>]*> 4ac41030 	c2	0xc41030
0000046c <[^>]*> 488620b0 	0x488620b0
00000470 <[^>]*> 4bcf21b0 	c2	0x1cf21b0
00000474 <[^>]*> 4bdf3130 	c2	0x1df3130
00000478 <[^>]*> 4ac20033 	c2	0xc20033
0000047c <[^>]*> 48862033 	0x48862033
00000480 <[^>]*> 4bcf3033 	c2	0x1cf3033
00000484 <[^>]*> 4bdf2033 	c2	0x1df2033
00000488 <[^>]*> 4ac20433 	c2	0xc20433
0000048c <[^>]*> 48862433 	0x48862433
00000490 <[^>]*> 4bcf3433 	c2	0x1cf3433
00000494 <[^>]*> 4bdf2433 	c2	0x1df2433
00000498 <[^>]*> 4ac20032 	c2	0xc20032
0000049c <[^>]*> 48862032 	0x48862032
000004a0 <[^>]*> 4bcf3032 	c2	0x1cf3032
000004a4 <[^>]*> 4bdf2032 	c2	0x1df2032
000004a8 <[^>]*> 4ac20432 	c2	0xc20432
000004ac <[^>]*> 48862432 	0x48862432
000004b0 <[^>]*> 4bcf3432 	c2	0x1cf3432
000004b4 <[^>]*> 4bdf2432 	c2	0x1df2432
000004b8 <[^>]*> 4ac4100f 	c2	0xc4100f
000004bc <[^>]*> 4886208f 	0x4886208f
000004c0 <[^>]*> 4bcf218f 	c2	0x1cf218f
000004c4 <[^>]*> 4bdf310f 	c2	0x1df310f
000004c8 <[^>]*> 4ac4100e 	c2	0xc4100e
000004cc <[^>]*> 4886208e 	0x4886208e
000004d0 <[^>]*> 4bcf218e 	c2	0x1cf218e
000004d4 <[^>]*> 4bdf310e 	c2	0x1df310e
000004d8 <[^>]*> 4ac41002 	c2	0xc41002
000004dc <[^>]*> 48862082 	0x48862082
000004e0 <[^>]*> 4bcf2182 	c2	0x1cf2182
000004e4 <[^>]*> 4bdf3102 	c2	0x1df3102
000004e8 <[^>]*> 4ac41003 	c2	0xc41003
000004ec <[^>]*> 48862083 	0x48862083
000004f0 <[^>]*> 4bcf2183 	c2	0x1cf2183
000004f4 <[^>]*> 4bdf3103 	c2	0x1df3103
000004f8 <[^>]*> 4ac4100a 	c2	0xc4100a
000004fc <[^>]*> 4886208a 	0x4886208a
00000500 <[^>]*> 4bcf218a 	c2	0x1cf218a
00000504 <[^>]*> 4bdf310a 	c2	0x1df310a
00000508 <[^>]*> 4ac4100d 	c2	0xc4100d
0000050c <[^>]*> 4886208d 	0x4886208d
00000510 <[^>]*> 4bcf218d 	c2	0x1cf218d
00000514 <[^>]*> 4bdf310d 	c2	0x1df310d
00000518 <[^>]*> 48a41018 	0x48a41018
0000051c <[^>]*> 4984101f 	0x4984101f
00000520 <[^>]*> 49c4101f 	0x49c4101f
00000524 <[^>]*> 4904101f 	0x4904101f
00000528 <[^>]*> 4944101f 	0x4944101f
0000052c <[^>]*> 48c62090 	0x48c62090
00000530 <[^>]*> 4bce3110 	c2	0x1ce3110
00000534 <[^>]*> 48c62092 	0x48c62092
00000538 <[^>]*> 4bce3112 	c2	0x1ce3112
0000053c <[^>]*> 4bcd00a0 	c2	0x1cd00a0
00000540 <[^>]*> 4a0000bf 	c2	0xbf
00000544 <[^>]*> 480000bf 	0x480000bf
00000548 <[^>]*> 490000bf 	bc2f	00000848 <[^>]*>
0000054c <[^>]*> 4a00103e 	c2	0x103e
00000550 <[^>]*> 4804103e 	0x4804103e
00000554 <[^>]*> 00c52046 	0xc52046
00000558 <[^>]*> 00252442 	0x252442
0000055c <[^>]*> 00c52056 	0xc52056
00000560 <[^>]*> 0025207e 	0x25207e
00000564 <[^>]*> 002520ba 	0x2520ba
00000568 <[^>]*> 4ca4200f 	prefx	0x4,a0\(a1\)
0000056c <[^>]*> 42000020 	wait
00000570 <[^>]*> 42000020 	wait
00000574 <[^>]*> 4359e260 	wait	0x56789
00000578 <[^>]*> 00000040 	ssnop
0000057c <[^>]*> 70831821 	clo	v1,a0
00000580 <[^>]*> 70831825 	dclo	v1,a0
00000584 <[^>]*> 70831820 	clz	v1,a0
00000588 <[^>]*> 70831824 	dclz	v1,a0
0000058c <[^>]*> 4c440005 	luxc1	\$f0,a0\(v0\)
00000590 <[^>]*> 4c44100d 	suxc1	\$f2,a0\(v0\)
00000594 <[^>]*> 42000008 	tlbp
00000598 <[^>]*> 42000001 	tlbr
	\.\.\.
