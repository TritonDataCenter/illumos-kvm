/*
 * Ported from Linux by Joyent.
 * Copyright 2011 Joyent, Inc.
 */
/*
 * XXX Need proper header files!
 */
#include "kvm_bitops.h"
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "kvm_iodev.h"
#include "kvm.h"
#include "apicdef.h"
#include "kvm_ioapic.h"
#include "kvm_lapic.h"
#include "kvm_irq.h"
#include "kvm_cache_regs.h"


unsigned long
kvm_register_read(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	if (!test_bit(reg, (unsigned long *)&vcpu->arch.regs_avail))
		kvm_x86_ops->cache_reg(vcpu, reg);

	return (vcpu->arch.regs[reg]);
}

void
kvm_register_write(struct kvm_vcpu *vcpu, enum kvm_reg reg, unsigned long val)
{
	vcpu->arch.regs[reg] = val;
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
}

unsigned long
kvm_rip_read(struct kvm_vcpu *vcpu)
{
	return (kvm_register_read(vcpu, VCPU_REGS_RIP));
}

void
kvm_rip_write(struct kvm_vcpu *vcpu, unsigned long val)
{
	kvm_register_write(vcpu, VCPU_REGS_RIP, val);
}

uint64_t
kvm_pdptr_read(struct kvm_vcpu *vcpu, int index)
{
	if (!test_bit(VCPU_EXREG_PDPTR,
	    (unsigned long *)&vcpu->arch.regs_avail)) {
		kvm_x86_ops->cache_reg(vcpu, VCPU_EXREG_PDPTR);
	}

	return (vcpu->arch.pdptrs[index]);
}

ulong
kvm_read_cr0_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR0_GUEST_BITS;

	if (tmask & vcpu->arch.cr0_guest_owned_bits)
		kvm_x86_ops->decache_cr0_guest_bits(vcpu);

	return (vcpu->arch.cr0 & mask);
}

ulong
kvm_read_cr0(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, ~0UL));
}

ulong
kvm_read_cr4_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	uint64_t tmask = mask & KVM_POSSIBLE_CR4_GUEST_BITS;

	if (tmask & vcpu->arch.cr4_guest_owned_bits)
		kvm_x86_ops->decache_cr4_guest_bits(vcpu);

	return (vcpu->arch.cr4 & mask);
}

ulong
kvm_read_cr4(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, ~0UL));
}
