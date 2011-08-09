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
 *
 * Derived from Linux Kernel ./arch/x86/include/asm/msr.h
 *
 * Copyright 2011 various Linux Kernel contributors.
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#ifndef _KVM_MSR_H
#define	_KVM_MSR_H

#include "msr-index.h"

#include <sys/ontrap.h>
#include <sys/errno.h>

typedef struct msr {
	union {
		struct {
			uint32_t l;
			uint32_t h;
		};
		uint64_t q;
	}b;
} msr_t;

typedef struct msr_info {
	uint32_t msr_no;
	struct msr reg;
	struct msr *msrs;
	int err;
} msr_info_t;

typedef struct msr_regs_info {
	uint32_t *regs;
	int err;
} msr_regs_info_t;

/*
 * both i386 and x86_64 returns 64-bit value in edx:eax, but gcc's "A"
 * constraint has different meanings. For i386, "A" means exactly
 * edx:eax, while for x86_64 it doesn't mean rdx:rax or edx:eax. Instead,
 * it means rax *or* rdx.
 */
#define	DECLARE_ARGS(val, low, high)	unsigned low, high
#define	EAX_EDX_VAL(val, low, high)	((low) | ((uint64_t)(high) << 32))
#define	EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define	EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)

extern unsigned long long native_read_msr(unsigned int);
extern uint64_t native_read_msr_safe(unsigned int, int *);
extern int native_write_msr_safe(unsigned int, unsigned, unsigned);
extern void native_write_msr(unsigned int, unsigned, unsigned);

extern unsigned long long native_read_tsc(void);
extern unsigned long long __native_read_tsc(void);

/*
 * Access to machine-specific registers (available on 586 and better only)
 * Note: the rd* operations modify the parameters directly (without using
 * pointer indirection), this allows gcc to optimize better
 */

#define	rdmsr(msr, val1, val2)						\
do {									\
	uint64_t __val = native_read_msr((msr));			\
	(val1) = (uint32_t)__val;					\
	(val2) = (uint32_t)(__val >> 32);				\
} while (0)

#define	rdmsrl(msr, val)						\
	((val) = native_read_msr((msr)))

#define	wrmsrl(msr, val)						\
	native_write_msr((msr), (uint32_t)((uint64_t)(val)),		\
	    (uint32_t)((uint64_t)(val) >> 32))

/* see comment above for wrmsr() */
/* wrmsr with exception handling */
extern int wrmsr_safe(unsigned msr, unsigned low, unsigned high);

/* rdmsr with exception handling */
/* BEGIN CSTYLED */
#define	rdmsr_safe(msr, p1, p2)					\
({								\
	int __err;						\
	uint64_t __val = native_read_msr_safe((msr), &__err);	\
	(*p1) = (uint32_t)__val;				\
	(*p2) = (uint32_t)(__val >> 32);			\
	__err;							\
})
/* END CSTYLED */

extern int rdmsrl_safe(unsigned, unsigned long long *);
extern int rdmsrl_amd_safe(unsigned, unsigned long long *);
extern int wrmsrl_amd_safe(unsigned, unsigned long long);

#define	rdtscl(low)						\
	((low) = (uint32_t)__native_read_tsc())

#define	rdtscll(val)						\
	((val) = __native_read_tsc())

#endif /* _KVM_MSR_H */
