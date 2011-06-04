/*
 * This header files contains pieces necessary for the illumos implementation of
 * the kvm driver. These definitions should not be exported to userland.
 */
#ifndef	__KVM_IMPL_H
#define	__KVM_IMPL_H

#include <sys/kstat.h>
#include <sys/sdt.h>

#define XXX_KVM_PROBE DTRACE_PROBE2(kvm__xxx, \
	char *, __FILE__, int, __LINE__)
#define XXX_KVM_SYNC_PROBE DTRACE_PROBE2(kvm__xxx__sync, \
	char *, __FILE__, int, __LINE__)

#define	KVM_TRACE1(name, type1, arg1)					\
	DTRACE_PROBE1(kvm__##name, type1, arg1);

#define	KVM_TRACE2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(kvm__##name, type1, arg1, type2, arg2);

#define	KVM_TRACE3(name, type1, arg1, type2, arg2, type3, arg3)		\
	DTRACE_PROBE3(kvm__##name, type1, arg1, type2, arg2, type3, arg3);

#define	KVM_TRACE4(name, type1, arg1, type2, arg2, type3, arg3,		\
	    type4, arg4)						\
	DTRACE_PROBE4(kvm__##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	KVM_TRACE5(name, type1, arg1, type2, arg2, type3, arg3,		\
	    type4, arg4, type5, arg5)					\
	DTRACE_PROBE5(kvm__##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5);

#define	KVM_TRACE6(name, type1, arg1, type2, arg2, type3, arg3,		\
	    type4, arg4, type5, arg5, type6, arg6)			\
	DTRACE_PROBE6(kvm__##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6);

typedef struct kvm_vcpu_stats {
       kstat_named_t kvmvs_id;                 /* instance of associated kvm */
       kstat_named_t kvmvs_nmi_injections;     /* number of NMI injections */
       kstat_named_t kvmvs_irq_injections;     /* number of IRQ injections */
       kstat_named_t kvmvs_fpu_reload;         /* number of FPU reloads */
       kstat_named_t kvmvs_host_state_reload;  /* host state (re)loads */
       kstat_named_t kvmvs_insn_emulation;     /* instruction emulation */
       kstat_named_t kvmvs_insn_emulation_fail; /* emulation failures */
       kstat_named_t kvmvs_exits;              /* total VM exits */
       kstat_named_t kvmvs_halt_exits;         /* exits due to HLT */
       kstat_named_t kvmvs_irq_exits;          /* exits due to IRQ */
       kstat_named_t kvmvs_io_exits;           /* exits due to I/O instrn */
       kstat_named_t kvmvs_mmio_exits;         /* exits due to mem mppd I/O */
       kstat_named_t kvmvs_nmi_window_exits;   /* exits due to NMI window */
       kstat_named_t kvmvs_irq_window_exits;   /* exits due to IRQ window */
       kstat_named_t kvmvs_request_irq_exits;  /* exits due to requested IRQ */
       kstat_named_t kvmvs_signal_exits;       /* exits due to pending sig */
       kstat_named_t kvmvs_halt_wakeup;        /* wakeups from HLT */
       kstat_named_t kvmvs_invlpg;             /* INVLPG instructions */
       kstat_named_t kvmvs_pf_guest;           /* injected guest pagefaults */
       kstat_named_t kvmvs_pf_fixed;           /* fixed pagefaults */
       kstat_named_t kvmvs_hypercalls;         /* hypercalls (VMCALL instrn) */
} kvm_vcpu_stats_t;

#define KVM_VCPU_KSTAT_INIT(vcpu, field, name) \
	kstat_named_init(&((vcpu)->kvcpu_stats.field), name, KSTAT_DATA_UINT64);

#define KVM_VCPU_KSTAT_INC(vcpu, field) \
	(vcpu)->kvcpu_stats.field.value.ui64++;

typedef struct kvm_stats {
       kstat_named_t kvmks_pid;                /* PID of opening process */
       kstat_named_t kvmks_mmu_pte_write;      /* page table entry writes */
       kstat_named_t kvmks_mmu_pte_zapped;     /* zapped page table entries */
       kstat_named_t kvmks_mmu_pte_updated;    /* page table entry updates */
       kstat_named_t kvmks_mmu_flooded;        /* # of pages flooded */
       kstat_named_t kvmks_mmu_cache_miss;     /* misses in page cache */
       kstat_named_t kvmks_mmu_recycled;       /* recycles from free list */
       kstat_named_t kvmks_remote_tlb_flush;   /* remote TLB flushes */
       kstat_named_t kvmks_lpages;             /* large pages in use */
} kvm_stats_t;

#define KVM_KSTAT_INIT(kvmp, field, name) \
	kstat_named_init(&((kvmp)->kvm_stats.field), name, KSTAT_DATA_UINT64);

#define KVM_KSTAT_INC(kvmp, field) \
	(kvmp)->kvm_stats.field.value.ui64++;

#define KVM_KSTAT_DEC(kvmp, field) \
	(kvmp)->kvm_stats.field.value.ui64--;


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif /*ARRAY_SIZE*/

#define KVM_CPUALL -1

typedef void (*kvm_xcall_t)(void *);

/*
 * XXX
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

#ifndef offsetof
#define offsetof(s, m) ((size_t)(&((s *)0)->m))
#endif

#endif
