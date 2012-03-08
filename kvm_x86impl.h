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
 * Copyright 2011 various Linux Kernel contributors.
 * Copyright (c) 2012 Joyent, Inc. All Rights Reserved.
 */

#ifndef __KVM_X86_IMPL_H
#define	__KVM_X86_IMPL_H

#include <sys/types.h>
#include <vm/page.h>

#include "kvm_host.h"
#include "kvm_x86.h"
#include "kvm_cache_regs.h"

extern void kvm_clear_exception_queue(struct kvm_vcpu *);
extern void kvm_queue_interrupt(struct kvm_vcpu *, uint8_t, int);
extern void kvm_clear_interrupt_queue(struct kvm_vcpu *);
extern int kvm_event_needs_reinjection(struct kvm_vcpu *);
extern int kvm_exception_is_soft(unsigned int nr);
extern kvm_cpuid_entry2_t *kvm_find_cpuid_entry(struct kvm_vcpu *,
    uint32_t, uint32_t);
extern int is_protmode(struct kvm_vcpu *);
extern int is_long_mode(struct kvm_vcpu *);
extern int is_pae(struct kvm_vcpu *);
extern int is_pse(struct kvm_vcpu *);
extern int is_paging(struct kvm_vcpu *);

extern caddr_t page_address(page_t *);
extern page_t *alloc_page(int, void **);
extern uint64_t kvm_va2pa(caddr_t);
extern page_t *pfn_to_page(pfn_t);
extern int zero_constructor(void *, void *, int);

#define	KVM_CPUALL -1

typedef void (*kvm_xcall_t)(void *);
extern void kvm_xcall(processorid_t, kvm_xcall_t, void *);
extern int kvm_xcall_func(kvm_xcall_t, void *);

extern unsigned long native_read_cr0(void);
#define	read_cr0()	(native_read_cr0())
extern unsigned long native_read_cr4(void);
#define	read_cr4()	(native_read_cr4())
extern unsigned long native_read_cr3(void);
#define	read_cr3()	(native_read_cr3())

extern page_t *compound_head(page_t *);
extern void get_page(page_t *);
extern unsigned long get_desc_limit(const struct desc_struct *);

extern unsigned long get_desc_base(const struct desc_struct *);
extern uint32_t bit(int);

#endif
