.PATH.S: ${.PARSEDIR}
EC_SRCS += \
ecp_nistz256-x86_64.S \
x25519-x86_64.S 

ECCPPFLAGS+= -DX25519_ASM -DOPENSSL_NO_EC_NISTP_64_GCC_128

ECNI = yes
.include "../../ec.inc"
