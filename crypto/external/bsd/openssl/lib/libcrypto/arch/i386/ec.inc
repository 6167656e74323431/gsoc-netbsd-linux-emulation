.PATH.S: ${.PARSEDIR}
EC_SRCS += \
ecp_nistz256-x86.S 

ECCPPFLAGS+= -DOPENSSL_NO_EC_NISTP_64_GCC_128

ECNI = yes
.include "../../ec.inc"
