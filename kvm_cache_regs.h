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
 * Copyright 1992, Linus Torvalds.
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#ifndef ASM_KVM_CACHE_REGS_H
#define	ASM_KVM_CACHE_REGS_H

#include <sys/types.h>

#include "kvm_host.h"
#include "processor-flags.h"

#define	KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define	KVM_POSSIBLE_CR4_GUEST_BITS				  \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR  \
	    | X86_CR4_OSXMMEXCPT | X86_CR4_PGE)

extern unsigned long kvm_register_read(struct kvm_vcpu *, enum kvm_reg);
extern void kvm_register_write(struct kvm_vcpu *, enum kvm_reg, unsigned long);
extern unsigned long kvm_rip_read(struct kvm_vcpu *);
extern void kvm_rip_write(struct kvm_vcpu *, unsigned long);
extern uint64_t kvm_pdptr_read(struct kvm_vcpu *, int);
extern ulong kvm_read_cr0_bits(struct kvm_vcpu *, ulong);
extern ulong kvm_read_cr0(struct kvm_vcpu *);
extern ulong kvm_read_cr4_bits(struct kvm_vcpu *, ulong);
extern ulong kvm_read_cr4(struct kvm_vcpu *);

#endif
