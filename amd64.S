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
 * void rflush(const void *addr, size_t n, size_t step);
 *
 * Flush a range from the cache.
 */
.global rflush
.type	rflush, @function
rflush:
	movq		%rsi, %rcx

rflush_loop:
	clflush		(%rdi)

	addq		%rdx, %rdi
	dec		%rcx
	jnz		rflush_loop

	ret

/*
 * uint64_t rdtsc64(void);
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
 * Read the 64-bit timestamp counter, but discard the upper half.
 */
.global rdtsc32
.type	rdtsc32, @function
rdtsc32:
	rdtsc

	ret

/*
 * uint64_t timeread(const void *addr);
 *
 * Read a word from the specified address and return the time it took
 * in delta-TSC.  Will occasionally return a wildly inaccurate number
 * due to counter wraparound.
 */
.global	timeread
.type	timeread, @function
timeread:
	mfence

	rdtsc
	shlq		$32, %rdx
	orq		%rdx, %rax
	movq		%rax, %rcx

	lfence
	movl		(%rdi), %eax
	lfence

	rdtsc
	shlq		$32, %rdx
	orq		%rdx, %rax
	subq		%rcx, %rax

	ret
