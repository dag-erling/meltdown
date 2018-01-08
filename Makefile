PROG	 = meltdown
SRCS	 = meltdown.c ${MACHINE_CPUARCH}.S
MAN	 = #

.include <bsd.prog.mk>
