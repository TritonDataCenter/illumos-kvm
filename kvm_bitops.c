/*
 * Copyright 1992, Linus Torvalds.
 *
 * Note: inlines with more than a single statement should be marked
 * __always_inline to avoid problems with older gcc's inlining heuristics.
 */

#include "kvm_bitops.h"

#include "kvm_impl.h"

#define	ADDR	BITOP_ADDR(addr)

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
inline void
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
inline void
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
inline void
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

/*
 * clear_bit_unlock - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and implies release semantics before the memory
 * operation. It can be used for an unlock.
 */
inline void
clear_bit_unlock(unsigned nr, volatile unsigned long *addr)
{
#ifdef XXX
	barrier();
#else
	XXX_KVM_SYNC_PROBE;
#endif
	clear_bit(nr, addr);
}

inline void
__clear_bit(int nr, volatile unsigned long *addr)
{
	__asm__ volatile("btr %1,%0" : ADDR : "Ir" (nr));
}


/*
 * __clear_bit_unlock - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * __clear_bit() is non-atomic and implies release semantics before the memory
 * operation. It can be used for an unlock if no other CPUs can concurrently
 * modify other bits in the word.
 *
 * No memory barrier is required here, because x86 cannot reorder stores past
 * older loads. Same principle as spin_unlock.
 */
inline void
__clear_bit_unlock(unsigned nr, volatile unsigned long *addr)
{
#ifdef XXX
	barrier();
#else
	XXX_KVM_SYNC_PROBE;
#endif
	__clear_bit(nr, addr);
}

#define	smp_mb__before_clear_bit()	barrier()
#define	smp_mb__after_clear_bit()	barrier()

/*
 * __change_bit - Toggle a bit in memory
 * @nr: the bit to change
 * @addr: the address to start counting from
 *
 * Unlike change_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
inline void
__change_bit(int nr, volatile unsigned long *addr)
{
	__asm__ volatile("btc %1,%0" : ADDR : "Ir" (nr));
}

/*
 * change_bit - Toggle a bit in memory
 * @nr: Bit to change
 * @addr: Address to start counting from
 *
 * change_bit() is atomic and may not be reordered.
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */
inline void
change_bit(int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		__asm__ volatile("lock xorb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((uint8_t)CONST_MASK(nr)));
	} else {
		__asm__ volatile("lock btc %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}

/*
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
inline int
test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("lock bts %2,%1\n\t"
	    "sbb %0,%0" : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return (oldbit);
}

/*
 * test_and_set_bit_lock - Set a bit and return its old value for lock
 * @nr: Bit to set
 * @addr: Address to count from
 *
 * This is the same as test_and_set_bit on x86.
 */
inline int
test_and_set_bit_lock(int nr, volatile unsigned long *addr)
{
	return (test_and_set_bit(nr, addr));
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
inline int
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
inline int
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
inline int
__test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("btr %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR
	    : "Ir" (nr));

	return (oldbit);
}

/* WARNING: non atomic and it can be reordered! */
inline int
__test_and_change_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("btc %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR
	    : "Ir" (nr) : "memory");

	return (oldbit);
}

/*
 * test_and_change_bit - Change a bit and return its old value
 * @nr: Bit to change
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
inline int
test_and_change_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("lock btc %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return (oldbit);
}

inline int
constant_test_bit(unsigned int nr, const volatile unsigned long *addr)
{
	return (((1UL << (nr % 64)) &
		(((unsigned long *)addr)[nr / 64])) != 0);
}

inline int
variable_test_bit(int nr, volatile const unsigned long *addr)
{
	int oldbit;

	__asm__ volatile("bt %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit)
	    : "m" (*(unsigned long *)addr), "Ir" (nr));

	return (oldbit);
}

#if 0 /* Fool kernel-doc since it doesn't do macros yet */
/*
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
int test_bit(int nr, const volatile unsigned long *addr);
#endif

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
inline unsigned long
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
inline unsigned long
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
inline unsigned long
__fls(unsigned long word)
{
	__asm__("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return (word);
}
