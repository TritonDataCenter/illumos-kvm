#!/usr/sbin/dtrace -Cs

#pragma D option quiet
#pragma D option switchrate=100hz

#include <sys/ioccom.h>

#define KVMIO 0xAE

#define KVM_RUN                   \
	(unsigned)_IO(KVMIO,   0x80)
#define KVM_GET_REGS              \
	(unsigned)_IOR(KVMIO,  0x81, struct kvm_regs)
#define KVM_SET_REGS              \
	(unsigned)_IOW(KVMIO,  0x82, struct kvm_regs)
#define KVM_GET_SREGS             \
	(unsigned)_IOR(KVMIO,  0x83, struct kvm_sregs)
#define KVM_SET_SREGS             \
	(unsigned)_IOW(KVMIO,  0x84, struct kvm_sregs)
#define KVM_INTERRUPT             \
	(unsigned)_IOW(KVMIO,  0x86, struct kvm_interrupt)
#define KVM_SET_CPUID             \
	(unsigned)_IOW(KVMIO,  0x8a, struct kvm_cpuid)
#define KVM_SET_SIGNAL_MASK       \
	(unsigned)_IOW(KVMIO,  0x8b, struct kvm_signal_mask)
#define KVM_GET_FPU               \
	(unsigned)_IOR(KVMIO,  0x8c, struct kvm_fpu)
#define KVM_SET_FPU               \
	(unsigned)_IOW(KVMIO,  0x8d, struct kvm_fpu)
#define KVM_GET_MSRS              \
	(unsigned)_IOWR(KVMIO, 0x88, struct kvm_msrs)
#define KVM_SET_MSRS              \
	(unsigned)_IOW(KVMIO,  0x89, struct kvm_msrs)
#define KVM_GET_LAPIC             \
	(unsigned)_IOR(KVMIO,  0x8e, struct kvm_lapic)
#define KVM_SET_LAPIC             \
	(unsigned)_IOW(KVMIO,  0x8f, struct kvm_lapic)
#define KVM_GET_MP_STATE          \
	(unsigned)_IOR(KVMIO,  0x98, struct kvm_mp_state)
#define KVM_SET_MP_STATE          \
	(unsigned)_IOW(KVMIO,  0x99, struct kvm_mp_state)
#define KVM_X86_SETUP_MCE         \
	(unsigned)_IOW(KVMIO,  0x9c, struct mcg_cap)
#define KVM_X86_GET_MCE_CAP_SUPPORTED \
	(unsigned)_IOR(KVMIO,  0x9d, uint64_t)
#define KVM_X86_SET_MCE           \
	(unsigned)_IOW(KVMIO,  0x9e, struct kvm_x86_mce)
#define KVM_REINJECT_CONTROL      \
	(unsigned)_IO(KVMIO,   0x71)
#define KVM_SET_BOOT_CPU_ID       \
	(unsigned)_IO(KVMIO,   0x78)
#define KVM_SET_CLOCK             \
	(unsigned)_IOW(KVMIO,  0x7b, struct kvm_clock_data)
#define KVM_GET_CLOCK             \
	(unsigned)_IOR(KVMIO,  0x7c, struct kvm_clock_data)
#define KVM_GET_VCPU_EVENTS       \
	(unsigned)_IOR(KVMIO,  0x9f, struct kvm_vcpu_events)
#define KVM_SET_VCPU_EVENTS       \
	(unsigned)_IOW(KVMIO,  0xa0, struct kvm_vcpu_events)
#define KVM_GET_PIT2              \
	(unsigned)_IOR(KVMIO,  0x9f, struct kvm_pit_state2)
#define KVM_SET_PIT2              \
	(unsigned)_IOW(KVMIO,  0xa0, struct kvm_pit_state2)
#define KVM_GET_API_VERSION       \
	(unsigned)_IO(KVMIO,   0x00)
#define KVM_CREATE_VM             \
	(unsigned)_IO(KVMIO,   0x01) /* returns a VM fd */
#define KVM_DESTROY_VM		  \
	(unsigned)_IO(KVMIO,   0x0a)
#define KVM_GET_MSR_INDEX_LIST    \
	(unsigned)_IOWR(KVMIO, 0x02, struct kvm_msr_list)
#define KVM_S390_ENABLE_SIE       \
	(unsigned)_IO(KVMIO,   0x06)
#define KVM_GET_VCPU_MMAP_SIZE    \
	(unsigned)_IO(KVMIO,   0x04) /* in bytes */
#define KVM_GET_SUPPORTED_CPUID   \
	(unsigned)_IOWR(KVMIO, 0x05, struct kvm_cpuid2)
#define KVM_CREATE_VCPU           \
	(unsigned)_IO(KVMIO,   0x41)
#define KVM_GET_DIRTY_LOG         \
	(unsigned)_IOW(KVMIO,  0x42, struct kvm_dirty_log)
#define KVM_SET_NR_MMU_PAGES      \
	(unsigned)_IO(KVMIO,   0x44)
#define KVM_GET_NR_MMU_PAGES      \
	(unsigned)_IO(KVMIO,   0x45)
#define KVM_SET_TSS_ADDR          \
	(unsigned)_IO(KVMIO,   0x47)
#define KVM_SET_IDENTITY_MAP_ADDR \
	(unsigned)_IOW(KVMIO,  0x48, struct kvm_id_map_addr_ioc)
#define KVM_CREATE_IRQCHIP        \
	(unsigned)_IO(KVMIO,   0x60)
#define KVM_IRQ_LINE              \
	(unsigned)_IOW(KVMIO,  0x61, struct kvm_irq_level_ioc)
#define KVM_IRQ_LINE_STATUS       \
	(unsigned)_IOWR(KVMIO, 0x67, struct kvm_irq_level_ioc)
#define KVM_GET_IRQCHIP           \
	(unsigned)_IOWR(KVMIO, 0x62, struct kvm_irqchip)
#define KVM_SET_IRQCHIP           \
	(unsigned)_IOR(KVMIO,  0x63, struct kvm_irqchip)
#define KVM_CREATE_PIT            \
	(unsigned)_IO(KVMIO,   0x64)
#define KVM_GET_PIT               \
	(unsigned)_IOWR(KVMIO, 0x65, struct kvm_pit_state)
#define KVM_SET_PIT               \
	(unsigned)_IOR(KVMIO,  0x66, struct kvm_pit_state)
#define KVM_CREATE_PIT2		  \
	(unsigned)_IOW(KVMIO,  0x77, struct kvm_pit_config_ioc)
#define KVM_SET_GSI_ROUTING       \
	(unsigned)_IOW(KVMIO,  0x6a, struct kvm_kirq_routing)
#define KVM_CHECK_EXTENSION       \
	(unsigned)_IO(KVMIO,   0x03)
#define KVM_SET_CPUID2            \
	(unsigned)_IOW(KVMIO,  0x90, struct kvm_cpuid2)
#define KVM_GET_CPUID2            \
	(unsigned)_IOWR(KVMIO, 0x91, struct kvm_cpuid2)
#define KVM_TPR_ACCESS_REPORTING  \
	(unsigned)_IOWR(KVMIO, 0x92, struct kvm_tpr_acl)
#define KVM_SET_VAPIC_ADDR        \
	(unsigned)_IOW(KVMIO,  0x93, struct kvm_vapic_addr)

#define KVM_SET_USER_MEMORY_REGION \
	(unsigned)_IOW(KVMIO, 0x46, struct kvm_userspace_memory_region)

inline string kvmioctl[uint32_t i] =
    i == KVM_RUN ? "KVM_RUN" :
    i == KVM_GET_REGS ? "KVM_GET_REGS" :
    i == KVM_SET_REGS ? "KVM_SET_REGS" :
    i == KVM_GET_SREGS ? "KVM_GET_SREGS" :
    i == KVM_SET_SREGS ? "KVM_SET_SREGS" :
    i == KVM_INTERRUPT ? "KVM_INTERRUPT" :
    i == KVM_SET_CPUID ? "KVM_SET_CPUID" :
    i == KVM_SET_SIGNAL_MASK ? "KVM_SET_SIGNAL_MASK" :
    i == KVM_GET_FPU ? "KVM_GET_FPU" :
    i == KVM_SET_FPU ? "KVM_SET_FPU" :
    i == KVM_GET_MSRS ? "KVM_GET_MSRS" :
    i == KVM_SET_MSRS ? "KVM_SET_MSRS" :
    i == KVM_GET_LAPIC ? "KVM_GET_LAPIC" :
    i == KVM_SET_LAPIC ? "KVM_SET_LAPIC" :
    i == KVM_GET_MP_STATE ? "KVM_GET_MP_STATE" :
    i == KVM_SET_MP_STATE ? "KVM_SET_MP_STATE" :
    i == KVM_X86_SETUP_MCE ? "KVM_X86_SETUP_MCE" :
    i == KVM_X86_GET_MCE_CAP_SUPPORTED ? "KVM_X86_GET_MCE_CAP_SUPPORTED" :
    i == KVM_X86_SET_MCE ? "KVM_X86_SET_MCE" :
    i == KVM_REINJECT_CONTROL ? "KVM_REINJECT_CONTROL" :
    i == KVM_SET_BOOT_CPU_ID ? "KVM_SET_BOOT_CPU_ID" :
    i == KVM_SET_CLOCK ? "KVM_SET_CLOCK" :
    i == KVM_GET_CLOCK ? "KVM_GET_CLOCK" :
    i == KVM_GET_VCPU_EVENTS ? "KVM_GET_VCPU_EVENTS" :
    i == KVM_SET_VCPU_EVENTS ? "KVM_SET_VCPU_EVENTS" :
    i == KVM_GET_PIT2 ? "KVM_GET_PIT2" :
    i == KVM_SET_PIT2 ? "KVM_SET_PIT2" :
    i == KVM_GET_API_VERSION ? "KVM_GET_API_VERSION" :
    i == KVM_CREATE_VM ? "KVM_CREATE_VM" :
    i == KVM_DESTROY_VM ? "KVM_DESTROY_VM" :
    i == KVM_GET_MSR_INDEX_LIST ? "KVM_GET_MSR_INDEX_LIST" :
    i == KVM_S390_ENABLE_SIE ? "KVM_S390_ENABLE_SIE" :
    i == KVM_GET_VCPU_MMAP_SIZE ? "KVM_GET_VCPU_MMAP_SIZE" :
    i == KVM_GET_SUPPORTED_CPUID ? "KVM_GET_SUPPORTED_CPUID" :
    i == KVM_CREATE_VCPU ? "KVM_CREATE_VCPU" :
    i == KVM_GET_DIRTY_LOG ? "KVM_GET_DIRTY_LOG" :
    i == KVM_SET_NR_MMU_PAGES ? "KVM_SET_NR_MMU_PAGES" :
    i == KVM_GET_NR_MMU_PAGES ? "KVM_GET_NR_MMU_PAGES" :
    i == KVM_SET_TSS_ADDR ? "KVM_SET_TSS_ADDR" :
    i == KVM_SET_IDENTITY_MAP_ADDR ? "KVM_SET_IDENTITY_MAP_ADDR" :
    i == KVM_CREATE_IRQCHIP ? "KVM_CREATE_IRQCHIP" :
    i == KVM_IRQ_LINE ? "KVM_IRQ_LINE" :
    i == KVM_IRQ_LINE_STATUS ? "KVM_IRQ_LINE_STATUS" :
    i == KVM_GET_IRQCHIP ? "KVM_GET_IRQCHIP" :
    i == KVM_SET_IRQCHIP ? "KVM_SET_IRQCHIP" :
    i == KVM_CREATE_PIT ? "KVM_CREATE_PIT" :
    i == KVM_GET_PIT ? "KVM_GET_PIT" :
    i == KVM_SET_PIT ? "KVM_SET_PIT" :
    i == KVM_CREATE_PIT2 ? "KVM_CREATE_PIT2" :
    i == KVM_SET_GSI_ROUTING ? "KVM_SET_GSI_ROUTING" :
    i == KVM_CHECK_EXTENSION ? "KVM_CHECK_EXTENSION" :
    i == KVM_SET_CPUID2 ? "KVM_SET_CPUID2" :
    i == KVM_GET_CPUID2 ? "KVM_GET_CPUID2" :
    i == KVM_TPR_ACCESS_REPORTING ? "KVM_TPR_ACCESS_REPORTING" :
    i == KVM_SET_VAPIC_ADDR ? "KVM_SET_VAPIC_ADDR" :
    i == KVM_SET_USER_MEMORY_REGION ? "KVM_SET_USER_MEMORY_REGION" :
    "<unknown>";

kvm_ioctl:entry
{
	printf("-> %d: %s (0x%x, tid %d)\n", timestamp,
	    kvmioctl[arg1], arg1, tid);
	self->cmd = arg1;
}

syscall::ioctl:return
/self->cmd/
{
	printf("<- %d: %s (0x%x, tid %d): %d (errno %d)\n", timestamp,
	    kvmioctl[self->cmd], self->cmd, tid, arg1, errno);
	self->cmd = 0;
}
