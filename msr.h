#ifndef _ASM_X86_MSR_H
#define _ASM_X86_MSR_H

#include "msr-index.h"

#ifndef __ASSEMBLY__


#define X86_IOC_RDMSR_REGS	_IOWR('c', 0xA0, __u32[8])
#define X86_IOC_WRMSR_REGS	_IOWR('c', 0xA1, __u32[8])

#ifdef _KERNEL

#include "asm.h"

#include <sys/errno.h>

#ifdef XXX
#include <asm/cpumask.h>
#endif /*XXX*/

struct msr {
	union {
		struct {
			uint32_t l;
			uint32_t h;
		};
		uint64_t q;
	}b;
};

struct msr_info {
	uint32_t msr_no;
	struct msr reg;
	struct msr *msrs;
	int err;
};

struct msr_regs_info {
	uint32_t *regs;
	int err;
};

static inline unsigned long long native_read_tscp(unsigned int *aux)
{
	unsigned long low, high;
	asm volatile(".byte 0x0f,0x01,0xf9"
		     : "=a" (low), "=d" (high), "=c" (*aux));
	return low | ((uint64_t)high << 32);
}

/*
 * both i386 and x86_64 returns 64-bit value in edx:eax, but gcc's "A"
 * constraint has different meanings. For i386, "A" means exactly
 * edx:eax, while for x86_64 it doesn't mean rdx:rax or edx:eax. Instead,
 * it means rax *or* rdx.
 */
#ifdef CONFIG_X86_64
#define DECLARE_ARGS(val, low, high)	unsigned low, high
#define EAX_EDX_VAL(val, low, high)	((low) | ((uint64_t)(high) << 32))
#define EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#else
#define DECLARE_ARGS(val, low, high)	unsigned long long val
#define EAX_EDX_VAL(val, low, high)	(val)
#define EAX_EDX_ARGS(val, low, high)	"A" (val)
#define EAX_EDX_RET(val, low, high)	"=A" (val)
#endif

static inline unsigned long long native_read_msr(unsigned int msr)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdmsr" : EAX_EDX_RET(val, low, high) : "c" (msr));
	return EAX_EDX_VAL(val, low, high);
}


static inline unsigned long long native_read_msr_safe(unsigned int msr,
						      int *err)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("2: rdmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=r" (*err), EAX_EDX_RET(val, low, high)
		     : "c" (msr), [fault] "i" (-EIO));
	return EAX_EDX_VAL(val, low, high);
}

static inline void native_write_msr(unsigned int msr,
				    unsigned low, unsigned high)
{
	asm volatile("wrmsr" : : "c" (msr), "a"(low), "d" (high) : "memory");
}

/* Can be uninlined because referenced by paravirt */
static inline int native_write_msr_safe(unsigned int msr,
					unsigned low, unsigned high)
{
	int err;
	asm volatile("2: wrmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=a" (err)
		     : "c" (msr), "0" (low), "d" (high),
		       [fault] "i" (-EIO)
		     : "memory");
	return err;
}

extern unsigned long long native_read_tsc(void);

extern int native_rdmsr_safe_regs(uint32_t regs[8]);
extern int native_wrmsr_safe_regs(uint32_t regs[8]);

static inline unsigned long long __native_read_tsc(void)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));

	return EAX_EDX_VAL(val, low, high);
}

static inline unsigned long long native_read_pmc(int counter)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdpmc" : EAX_EDX_RET(val, low, high) : "c" (counter));
	return EAX_EDX_VAL(val, low, high);
}

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

static inline void wrmsr(unsigned msr, unsigned low, unsigned high)
{
	native_write_msr(msr, low, high);
}

#define rdmsrl(msr, val)			\
	((val) = native_read_msr((msr)))

#define wrmsrl(msr, val)						\
	native_write_msr((msr), (uint32_t)((uint64_t)(val)), (uint32_t)((uint64_t)(val) >> 32))

/* wrmsr with exception handling */
static inline int wrmsr_safe(unsigned msr, unsigned low, unsigned high)
{
	return native_write_msr_safe(msr, low, high);
}

/* rdmsr with exception handling */
#define rdmsr_safe(msr, p1, p2)					\
({								\
	int __err;						\
	uint64_t __val = native_read_msr_safe((msr), &__err);	\
	(*p1) = (uint32_t)__val;					\
	(*p2) = (uint32_t)(__val >> 32);				\
	__err;							\
})

static inline int rdmsrl_safe(unsigned msr, unsigned long long *p)
{
	int err;

	*p = native_read_msr_safe(msr, &err);
	return err;
}

static inline int rdmsrl_amd_safe(unsigned msr, unsigned long long *p)
{
	uint32_t gprs[8] = { 0 };
	int err;

	gprs[1] = msr;
	gprs[7] = 0x9c5a203a;

	err = native_rdmsr_safe_regs(gprs);

	*p = gprs[0] | ((uint64_t)gprs[2] << 32);

	return err;
}

static inline int wrmsrl_amd_safe(unsigned msr, unsigned long long val)
{
	uint32_t gprs[8] = { 0 };

	gprs[0] = (uint32_t)val;
	gprs[1] = msr;
	gprs[2] = val >> 32;
	gprs[7] = 0x9c5a203a;

	return native_wrmsr_safe_regs(gprs);
}

static inline int rdmsr_safe_regs(uint32_t regs[8])
{
	return native_rdmsr_safe_regs(regs);
}

static inline int wrmsr_safe_regs(uint32_t regs[8])
{
	return native_wrmsr_safe_regs(regs);
}

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

#define rdtscp(low, high, aux)					\
do {                                                            \
	unsigned long long _val = native_read_tscp(&(aux));     \
	(low) = (uint32_t)_val;                                      \
	(high) = (uint32_t)(_val >> 32);                             \
} while (0)

#define rdtscpll(val, aux) (val) = native_read_tscp(&(aux))

#endif	/* !CONFIG_PARAVIRT */


#define checking_wrmsrl(msr, val) wrmsr_safe((msr), (uint32_t)(val),		\
					     (uint32_t)((val) >> 32))

#define write_tsc(val1, val2) wrmsr(MSR_IA32_TSC, (val1), (val2))

#define write_rdtscp_aux(val) wrmsr(MSR_TSC_AUX, (val), 0)

struct msr *msrs_alloc(void);
void msrs_free(struct msr *msrs);

#ifdef CONFIG_SMP
int rdmsr_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t *l, uint32_t *h);
int wrmsr_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t l, uint32_t h);
#ifdef XXX
void rdmsr_on_cpus(const struct cpumask *mask, uint32_t msr_no, struct msr *msrs);
void wrmsr_on_cpus(const struct cpumask *mask, uint32_t msr_no, struct msr *msrs);
#endif /*XXX*/
int rdmsr_safe_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t *l, uint32_t *h);
int wrmsr_safe_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t l, uint32_t h);
int rdmsr_safe_regs_on_cpu(unsigned int cpu, uint32_t regs[8]);
int wrmsr_safe_regs_on_cpu(unsigned int cpu, uint32_t regs[8]);
#else  /*  CONFIG_SMP  */
static inline int rdmsr_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t *l, uint32_t *h)
{
	rdmsr(msr_no, *l, *h);
	return 0;
}
static inline int wrmsr_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t l, uint32_t h)
{
	wrmsr(msr_no, l, h);
	return 0;
}
#ifdef XXX
static inline void rdmsr_on_cpus(const struct cpumask *m, uint32_t msr_no,
				struct msr *msrs)
{
       rdmsr_on_cpu(0, msr_no, &(msrs[0].l), &(msrs[0].h));
}
static inline void wrmsr_on_cpus(const struct cpumask *m, uint32_t msr_no,
				struct msr *msrs)
{
       wrmsr_on_cpu(0, msr_no, msrs[0].l, msrs[0].h);
}
#endif
static inline int rdmsr_safe_on_cpu(unsigned int cpu, uint32_t msr_no,
				    uint32_t *l, uint32_t *h)
{
	return rdmsr_safe(msr_no, l, h);
}
static inline int wrmsr_safe_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t l, uint32_t h)
{
	return wrmsr_safe(msr_no, l, h);
}
static inline int rdmsr_safe_regs_on_cpu(unsigned int cpu, uint32_t regs[8])
{
	return rdmsr_safe_regs(regs);
}
static inline int wrmsr_safe_regs_on_cpu(unsigned int cpu, uint32_t regs[8])
{
	return wrmsr_safe_regs(regs);
}
#endif  /* CONFIG_SMP */
#endif /* _KERNEL */
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_MSR_H */
