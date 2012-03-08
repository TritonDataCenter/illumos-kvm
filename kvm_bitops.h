/*
 * GPL HEADER START
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * GPL HEADER END
 */

#ifndef _ASM_X86_BITOPS_H
#define	_ASM_X86_BITOPS_H

/*
 * Copyright 1992, Linus Torvalds.
 * Copyright (c) 2012, Joyent, Inc.
 *
 * Note: inlines with more than a single statement should be marked
 * __always_inline to avoid problems with older gcc's inlining heuristics.
 */

#include <sys/types.h>

#define	DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define	BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, 8 * sizeof (long))

/*
 * These have to be done with inline assembly: that way the bit-setting
 * is guaranteed to be atomic. All bit operations return 0 if the bit
 * was cleared before the operation and != 0 if it was not.
 *
 * bit 0 is the LSB of addr; bit 32 is the LSB of (addr+1).
 */
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/*
 * Technically wrong, but this avoids compilation errors on some gcc
 * versions.
 */
#define	BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define	BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define	ADDR	BITOP_ADDR(addr)

/*
 * We do the locked ops that don't return the old value as
 * a mask operation on a byte.
 */
#define	IS_IMMEDIATE(nr)		(__builtin_constant_p(nr))
#define	CONST_MASK_ADDR(nr, addr)	\
	BITOP_ADDR((uintptr_t)(addr) + ((nr) >> 3))
#define	CONST_MASK(nr)			(1 << ((nr) & 7))

/*
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may not be reordered.  See __set_bit()
 * if you do not require the atomic guarantees.
 *
 * Note: there are no guarantees that this function will not be reordered
 * on non x86 architectures, so if you are writing portable code,
 * make sure not to rely on its reordering guarantees.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
static inline void
set_bit(unsigned int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		__asm__ volatile("lock orb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((uint8_t)CONST_MASK(nr))
			: "memory");
	} else {
		__asm__ volatile("lock bts %1,%0"
			: BITOP_ADDR(addr) : "Ir" (nr) : "memory");
	}
}

/*
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline void
__set_bit(int nr, volatile unsigned long *addr)
{
	__asm__ volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
}

/*
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static inline void
clear_bit(int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		__asm__ volatile("lock andb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((uint8_t)~CONST_MASK(nr)));
	} else {
		__asm__ volatile("lock btr %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}

static inline void
__clear_bit(int nr, volatile unsigned long *addr)
{
	__asm__ volatile("btr %1,%0" : ADDR : "Ir" (nr));
}

/*
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int
test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("lock bts %2,%1\n\t"
	    "sbb %0,%0" : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return (oldbit);
}

/*
 * __test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int
__test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__("bts %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR
	    : "Ir" (nr));
	return (oldbit);
}

/*
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int
test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("lock btr %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return (oldbit);
}

/*
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int
__test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("btr %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR
	    : "Ir" (nr));

	return (oldbit);
}

static inline int
constant_test_bit(unsigned int nr, const volatile unsigned long *addr)
{
	return (((1UL << (nr % 64)) &
		(((unsigned long *)addr)[nr / 64])) != 0);
}

static inline int
variable_test_bit(int nr, volatile const unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("bt %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit)
	    : "m" (*(unsigned long *)addr), "Ir" (nr));

	return (oldbit);
}

/*
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */

#define	test_bit(nr, addr)			\
	(__builtin_constant_p((nr))		\
	? constant_test_bit((nr), (addr))	\
	: variable_test_bit((nr), (addr)))

/*
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long
__ffs(unsigned long word)
{
	__asm__("bsf %1,%0"
		: "=r" (word)
		: "rm" (word));
	return (word);
}

/*
 * ffz - find first zero bit in word
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static inline unsigned long
ffz(unsigned long word)
{
	__asm__("bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return (word);
}

/*
 * __fls: find last set bit in word
 * @word: The word to search
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 */
static inline unsigned long
__fls(unsigned long word)
{
	__asm__("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return (word);
}

#endif /* _ASM_X86_BITOPS_H */
