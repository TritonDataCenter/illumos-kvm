#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/cpuvar.h>
#include <sys/segments.h>

#include "msr.h"
#include "vmx.h"
#include "irqflags.h"
#include "kvm_iodev.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "kvm.h"

extern int lwp_sigmask(int, uint_t, uint_t, uint_t, uint_t);

unsigned long
kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot)
{
	return (BT_SIZEOFMAP(memslot->npages));
}

struct kvm_vcpu *
kvm_get_vcpu(struct kvm *kvm, int i)
{
#ifdef XXX
	smp_rmb();
#endif
	return (kvm->vcpus[i]);
}

void
kvm_fx_save(struct i387_fxsave_struct *image)
{
	__asm__("fxsave (%0)":: "r" (image));
}

void
kvm_fx_restore(struct i387_fxsave_struct *image)
{
	__asm__("fxrstor (%0)":: "r" (image));
}

void
kvm_fx_finit(void)
{
	__asm__("finit");
}

uint32_t
get_rdx_init_val(void)
{
	return (0x600); /* P6 family */
}

void
kvm_inject_gp(struct kvm_vcpu *vcpu, uint32_t error_code)
{
	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
}

void
kvm_sigprocmask(int how, sigset_t *setp, sigset_t *osetp)
{
	k_sigset_t kset;

	ASSERT(how == SIG_SETMASK);
	ASSERT(setp != NULL);

	sigutok(setp, &kset);

	if (osetp != NULL)
		sigktou(&curthread->t_hold, osetp);

	(void) lwp_sigmask(SIG_SETMASK,
	    kset.__sigbits[0], kset.__sigbits[1], kset.__sigbits[2], 0);
}

unsigned long long
native_read_tscp(unsigned int *aux)
{
	unsigned long low, high;
	__asm__ volatile(".byte 0x0f,0x01,0xf9"
		: "=a" (low), "=d" (high), "=c" (*aux));
	return (low | ((uint64_t)high << 32));
}

unsigned long long
native_read_msr(unsigned int msr)
{
	DECLARE_ARGS(val, low, high);

	__asm__ volatile("rdmsr" : EAX_EDX_RET(val, low, high) : "c" (msr));
	return (EAX_EDX_VAL(val, low, high));
}

void
native_write_msr(unsigned int msr, unsigned low, unsigned high)
{
	__asm__ volatile("wrmsr" : : "c" (msr),
	    "a"(low), "d" (high) : "memory");
}

unsigned long long
__native_read_tsc(void)
{
	DECLARE_ARGS(val, low, high);

	__asm__ volatile("rdtsc" : EAX_EDX_RET(val, low, high));

	return (EAX_EDX_VAL(val, low, high));
}

unsigned long long
native_read_pmc(int counter)
{
	DECLARE_ARGS(val, low, high);

	__asm__ volatile("rdpmc" : EAX_EDX_RET(val, low, high) : "c" (counter));
	return (EAX_EDX_VAL(val, low, high));
}

int
wrmsr_safe(unsigned msr, unsigned low, unsigned high)
{
	return (native_write_msr_safe(msr, low, high));
}

int
rdmsrl_safe(unsigned msr, unsigned long long *p)
{
	int err;

	*p = native_read_msr_safe(msr, &err);
	return (err);
}

int
rdmsr_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t *l, uint32_t *h)
{
	rdmsr(msr_no, *l, *h);
	return (0);
}

int
wrmsr_on_cpu(unsigned int cpu, uint32_t msr_no, uint32_t l, uint32_t h)
{
	wrmsr(msr_no, l, h);
	return (0);
}

unsigned long
read_msr(unsigned long msr)
{
	uint64_t value;

	rdmsrl(msr, value);
	return (value);
}

unsigned long
kvm_read_tr_base(void)
{
	unsigned short tr;
	__asm__("str %0" : "=g"(tr));
	return (segment_base(tr));
}

int
kvm_xcall_func(kvm_xcall_t func, void *arg)
{
	if (func != NULL)
		(*func)(arg);

	return (0);
}

void
kvm_xcall(processorid_t cpu, kvm_xcall_t func, void *arg)
{
	cpuset_t set;

	CPUSET_ZERO(set);

	if (cpu == KVM_CPUALL) {
		CPUSET_ALL(set);
	} else {
		CPUSET_ADD(set, cpu);
	}

	kpreempt_disable();
	xc_sync((xc_arg_t)func, (xc_arg_t)arg, 0, CPUSET2BV(set),
		(xc_func_t) kvm_xcall_func);
	kpreempt_enable();
}

uint32_t
bit(int bitno)
{
	return (1 << (bitno & 31));
}

int
is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return (vcpu->arch.efer & EFER_LMA);
#else
	return (0);
#endif
}

unsigned short
kvm_read_fs(void)
{
	unsigned short seg;
	__asm__("mov %%fs, %0" : "=g"(seg));
	return (seg);
}

unsigned short
kvm_read_gs(void)
{
	unsigned short seg;
	__asm__("mov %%gs, %0" : "=g"(seg));
	return (seg);
}

unsigned short
kvm_read_ldt(void)
{
	unsigned short ldt;
	__asm__("sldt %0" : "=g"(ldt));
	return (ldt);
}

void
kvm_load_fs(unsigned short sel)
{
	__asm__("mov %0, %%fs" : : "rm"(sel));
}

void
kvm_load_gs(unsigned short sel)
{
	__asm__("mov %0, %%gs" : : "rm"(sel));
}

void
kvm_load_ldt(unsigned short sel)
{
	__asm__("lldt %0" : : "rm"(sel));
}


void
kvm_get_idt(struct descriptor_table *table)
{
	__asm__("sidt %0" : "=m"(*table));
}

void
kvm_get_gdt(struct descriptor_table *table)
{
	__asm__("sgdt %0" : "=m"(*table));
}
