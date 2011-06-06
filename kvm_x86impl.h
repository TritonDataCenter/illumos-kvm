/*
 * This contains functions that are x86 specific and part of the internal
 * implementation.
 */
#ifndef __KVM_X86_IMPL_H
#define	__KVM_X86_IMPL_H

#include <sys/types.h>

#include "kvm_host.h"
#include "kvm_x86.h"
#include "kvm_cache_regs.h"

inline void kvm_clear_exception_queue(struct kvm_vcpu *);
inline void kvm_queue_interrupt(struct kvm_vcpu *vcpu, uint8_t vector,
    int soft);
inline void kvm_clear_interrupt_queue(struct kvm_vcpu *vcpu);
inline int kvm_event_needs_reinjection(struct kvm_vcpu *vcpu);
inline int kvm_exception_is_soft(unsigned int nr);
kvm_cpuid_entry2_t *kvm_find_cpuid_entry(struct kvm_vcpu *vcpu,
    uint32_t function, uint32_t index);
inline int is_protmode(struct kvm_vcpu *vcpu);
inline int is_long_mode(struct kvm_vcpu *vcpu);
inline int is_pae(struct kvm_vcpu *vcpu);
inline int is_pse(struct kvm_vcpu *vcpu);
inline int is_paging(struct kvm_vcpu *vcpu);

caddr_t page_address(page_t *page);
extern page_t *alloc_page(size_t, int);
extern uint64_t kvm_va2pa(caddr_t va);
extern void bitmap_zero(unsigned long *, int);
extern page_t *pfn_to_page(pfn_t);
extern int zero_constructor(void *, void *, int);

#define KVM_CPUALL -1

typedef void (*kvm_xcall_t)(void *);
extern void kvm_xcall(processorid_t cpu, kvm_xcall_t func, void *arg);

/*
 * All the follwoing definitions are ones that are expected to just be in
 * x86/x86.c by Linux. However we currently have the things that need them
 * spread out across two files. For now we are putting them here, but this
 * should not last very long.
 */
#define KVM_NR_SHARED_MSRS 16

typedef struct kvm_shared_msrs_global {
	int nr;
	uint32_t msrs[KVM_NR_SHARED_MSRS];
} kvm_shared_msrs_global_t;

struct kvm_vcpu;

typedef struct kvm_user_return_notifier {
	void (*on_user_return)(struct kvm_vcpu *,
	    struct kvm_user_return_notifier *);
} kvm_user_return_notifier_t;

typedef struct kvm_shared_msrs {
	struct kvm_user_return_notifier urn;
	int registered;
	struct kvm_shared_msr_values {
		uint64_t host;
		uint64_t curr;
	} values[KVM_NR_SHARED_MSRS];
} kvm_shared_msrs_t;

/*
 * fxsave fpu state.  Taken from x86_64/processor.h.  To be killed when
 * we have asm/x86/processor.h
 */
typedef struct fxsave {
	uint16_t	cwd;
	uint16_t	swd;
	uint16_t	twd;
	uint16_t	fop;
	uint64_t	rip;
	uint64_t	rdp;
	uint32_t	mxcsr;
	uint32_t	mxcsr_mask;
	uint32_t	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
#ifdef CONFIG_X86_64
	uint32_t	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
#else
	uint32_t	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
#endif
} fxsave_t;

unsigned long native_read_cr0(void);
#define	read_cr0()	(native_read_cr0())
unsigned long native_read_cr4(void);
#define	read_cr4()	(native_read_cr4())
unsigned long native_read_cr3(void);
#define	read_cr3()	(native_read_cr3())

uint32_t bit(int bitno);
#endif
