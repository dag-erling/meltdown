PROGS		 = mdattack
SRCS.common	 = meltdown.c util.c
SRCS.common	+= ${MACHINE_CPUARCH}.S
SRCS.mdattack	 = mdattack.c ${SRCS.common}
MAN		 = #

.include <bsd.progs.mk>
