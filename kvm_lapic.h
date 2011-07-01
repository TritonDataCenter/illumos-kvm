#ifndef __KVM_X86_LAPIC_H
#define	__KVM_X86_LAPIC_H

#include <vm/page.h>

#include "kvm_iodev.h"
#include "kvm_timer.h"

#define	APIC_LVT_NUM			6
/* 14 is the version for Xeon and Pentium 8.4.8 */
#define	APIC_VERSION			(0x14UL | ((APIC_LVT_NUM - 1) << 16))

typedef struct kvm_lapic {
	unsigned long base_address;
	struct kvm_io_device dev;
	struct kvm_timer lapic_timer;
	uint32_t divide_count;
	struct kvm_vcpu *vcpu;
	int irr_pending;
	void *regs;
	gpa_t vapic_addr;
	page_t *vapic_page;
} kvm_lapic_t;

extern int kvm_create_lapic(struct kvm_vcpu *);
extern void kvm_lapic_reset(struct kvm_vcpu *);
extern void kvm_free_lapic(struct kvm_vcpu *);

extern void kvm_apic_set_version(struct kvm_vcpu *);
extern int kvm_apic_present(struct kvm_vcpu *vcpu);

extern void kvm_lapic_sync_from_vapic(struct kvm_vcpu *);
extern void kvm_lapic_sync_to_vapic(struct kvm_vcpu *);

extern int kvm_apic_has_interrupt(struct kvm_vcpu *);
extern int kvm_apic_accept_pic_intr(struct kvm_vcpu *);
extern int kvm_get_apic_interrupt(struct kvm_vcpu *);
extern int kvm_apic_match_dest(struct kvm_vcpu *, struct kvm_lapic *,
    int, int, int);

extern int kvm_lapic_enabled(struct kvm_vcpu *);
extern uint64_t kvm_lapic_get_cr8(struct kvm_vcpu *);
extern int kvm_lapic_find_highest_irr(struct kvm_vcpu *);
extern int kvm_apic_set_irq(struct kvm_vcpu *, struct kvm_lapic_irq *);
extern int kvm_apic_compare_prio(struct kvm_vcpu *, struct kvm_vcpu *);

extern void kvm_lapic_set_tpr(struct kvm_vcpu *, unsigned long);
extern void kvm_lapic_set_base(struct kvm_vcpu *, uint64_t);
extern int kvm_lapic_set_vapic_addr(struct kvm_vcpu *, struct kvm_vapic_addr *);

extern int kvm_x2apic_msr_write(struct kvm_vcpu *, uint32_t, uint64_t);
extern int kvm_x2apic_msr_read(struct kvm_vcpu *, uint32_t, uint64_t *);

extern int kvm_hv_vapic_msr_write(struct kvm_vcpu *, uint32_t, uint64_t);
extern int kvm_hv_vapic_msr_read(struct kvm_vcpu *, uint32_t, uint64_t *);

extern uint64_t kvm_get_apic_base(struct kvm_vcpu *);
extern void kvm_set_apic_base(struct kvm_vcpu *, uint64_t);

extern int kvm_irq_delivery_to_apic(struct kvm *,
    struct kvm_lapic *, struct kvm_lapic_irq *);
extern void kvm_apic_post_state_restore(struct kvm_vcpu *);

#endif
