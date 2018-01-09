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
 * void clflush(const void *addr);
 *
 * Flush an address from the cache.
 */
.global clflush
.type	clflush, @function
clflush:
	clflush		(%rdi)
	ret

/*
 * uint64_t rdtsc64(void);
 *
 * entry:
 *	-
 * exit:
 *	%rax	TSC value
 *
 * Read the 64-bit timestamp counter.
 */
.global rdtsc64
.type	rdtsc64, @function
rdtsc64:
	rdtsc
	shlq		$32, %rdx
	orq		%rdx, %rax

	ret

/*
 * uint32_t rdtsc32(void);
 *
 * entry:
 *	-
 * exit:
 *	%eax	lower 32 bits of TSC value
 *
 * Read the 64-bit timestamp counter, but discard the upper half.
 */
.global rdtsc32
.type	rdtsc32, @function
rdtsc32:
	rdtsc

	ret

/*
 * uint64_t timed_read(const void *addr);
 *
 * entry:
 *      %rdi	addr
 * exit:
 *      %rax	TSC delta
 *
 * Read a word from the specified address and return the time it took
 * in delta-TSC.  Will occasionally return a wildly inaccurate number
 * due to counter wraparound.
 */
.global	timed_read
.type	timed_read, @function
timed_read:
	mfence
	lfence

	rdtsc
	shlq		$32, %rdx
	orq		%rdx, %rax
	movq		%rax, %rcx

	movl		(%rdi), %eax
	lfence

	rdtsc
	shlq		$32, %rdx
	orq		%rdx, %rax
	subq		%rcx, %rax

	ret

/*
 * void spec_read(const uint8_t *addr, const uint8_t *probe, unsigned int shift);
 *
 * entry:
 *      %rdi	addr
 *      %rsi	probe
 *      %rdx	shift
 * exit:
 *	-
 *
 * Read *addr repeatedly until it is non-zero, then read probe[*addr << shift].
 */
.global spec_read
.type	spec_read, @function
spec_read:
	xor		%rax, %rax
	movq		%rdx, %rcx

1:
	movb		(%rdi), %al
	testq		%rax, %rax
	jz		1b

	shlq		%cl, %rax
	movb		(%rax, %rsi, 1), %cl

	ret
