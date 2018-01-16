PROG	 = meltdown
SRCS	 = main.c meltdown.c util.c
SRCS	+= ${MACHINE_CPUARCH}.S
MAN	 = #

.include <bsd.prog.mk>
