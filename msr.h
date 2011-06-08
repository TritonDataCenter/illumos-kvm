#ifndef _ASM_X86_MSR_H
#define _ASM_X86_MSR_H

#include "msr-index.h"

#ifndef __ASSEMBLY__


#define X86_IOC_RDMSR_REGS	_IOWR('c', 0xA0, __u32[8])
#define X86_IOC_WRMSR_REGS	_IOWR('c', 0xA1, __u32[8])

#ifdef _KERNEL

#include "asm.h"
#include <sys/ontrap.h>
#include <sys/errno.h>

#ifdef XXX
#include <asm/cpumask.h>
#endif /*XXX*/

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

extern unsigned long long native_read_tscp(unsigned int *aux);

/*
 * both i386 and x86_64 returns 64-bit value in edx:eax, but gcc's "A"
 * constraint has different meanings. For i386, "A" means exactly
 * edx:eax, while for x86_64 it doesn't mean rdx:rax or edx:eax. Instead,
 * it means rax *or* rdx.
 */
#define DECLARE_ARGS(val, low, high)	unsigned low, high
#define EAX_EDX_VAL(val, low, high)	((low) | ((uint64_t)(high) << 32))
#define EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)

extern unsigned long long native_read_msr(unsigned int msr);
extern uint64_t native_read_msr_safe(unsigned int msr, int *err);
extern int native_write_msr_safe(unsigned int msr,
				 unsigned low, unsigned high);

extern void native_write_msr(unsigned int msr,
				    unsigned low, unsigned high);

extern unsigned long long native_read_tsc(void);

extern unsigned long long __native_read_tsc(void);
extern unsigned long long native_read_pmc(int counter);

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else

#ifdef XXX
#include <linux/errno.h>
#endif /*XXX*/
/*
 * Access to machine-specific registers (available on 586 and better only)
 * Note: the rd* operations modify the parameters directly (without using
 * pointer indirection), this allows gcc to optimize better
 */

#define rdmsr(msr, val1, val2)					\
do {								\
	uint64_t __val = native_read_msr((msr));			\
	(val1) = (uint32_t)__val;					\
	(val2) = (uint32_t)(__val >> 32);				\
} while (0)

#define rdmsrl(msr, val)			\
	((val) = native_read_msr((msr)))

#define wrmsrl(msr, val)						\
	native_write_msr((msr), (uint32_t)((uint64_t)(val)), (uint32_t)((uint64_t)(val) >> 32))

/* see comment above for wrmsr() */
/* wrmsr with exception handling */
extern int wrmsr_safe(unsigned msr, unsigned low, unsigned high);

/* rdmsr with exception handling */
#define rdmsr_safe(msr, p1, p2)					\
({								\
	int __err;						\
	uint64_t __val = native_read_msr_safe((msr), &__err);	\
	(*p1) = (uint32_t)__val;					\
	(*p2) = (uint32_t)(__val >> 32);				\
	__err;							\
})

extern int rdmsrl_safe(unsigned msr, unsigned long long *p);

extern int rdmsrl_amd_safe(unsigned msr, unsigned long long *p);
extern int wrmsrl_amd_safe(unsigned msr, unsigned long long val);

#define rdtscl(low)						\
	((low) = (uint32_t)__native_read_tsc())

#define rdtscll(val)						\
	((val) = __native_read_tsc())

#define rdpmc(counter, low, high)			\
do {							\
	uint64_t _l = native_read_pmc((counter));		\
	(low)  = (uint32_t)_l;				\
	(high) = (uint32_t)(_l >> 32);			\
} while (0)

#endif	/* !CONFIG_PARAVIRT */


#define checking_wrmsrl(msr, val) wrmsr_safe((msr), (uint32_t)(val),		\
					     (uint32_t)((val) >> 32))

#define write_tsc(val1, val2) wrmsr(MSR_IA32_TSC, (val1), (val2))

#define write_rdtscp_aux(val) wrmsr(MSR_TSC_AUX, (val), 0)

struct msr *msrs_alloc(void);
void msrs_free(struct msr *msrs);

#endif /* _KERNEL */
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_H */
