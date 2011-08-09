/*
 * kvm_irq.h: in kernel interrupt controller related definitions
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#ifndef __IRQ_H
#define	__IRQ_H

#include <sys/mutex.h>
#include "kvm_host.h"

#include "kvm_iodev.h"
#include "kvm_ioapic.h"
#include "kvm_lapic.h"

#define	PIC_NUM_PINS 16
#define	SELECT_PIC(irq) \
	((irq) < 8 ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE)

struct kvm;
struct kvm_vcpu;

typedef void irq_request_func(void *opaque, int level);

typedef struct kvm_kpic_state {
	uint8_t last_irr;	/* edge detection */
	uint8_t irr;		/* interrupt request register */
	uint8_t imr;		/* interrupt mask register */
	uint8_t isr;		/* interrupt service register */
	uint8_t isr_ack;	/* interrupt ack detection */
	uint8_t priority_add;	/* highest irq priority */
	uint8_t irq_base;
	uint8_t read_reg_select;
	uint8_t poll;
	uint8_t special_mask;
	uint8_t init_state;
	uint8_t auto_eoi;
	uint8_t rotate_on_auto_eoi;
	uint8_t special_fully_nested_mode;
	uint8_t init4;		/* true if 4 byte init */
	uint8_t elcr;		/* PIIX edge/trigger selection */
	uint8_t elcr_mask;
	struct kvm_pic *pics_state;
} kvm_kpic_state_t;

typedef struct kvm_pic {
	kmutex_t lock;
	unsigned pending_acks;
	struct kvm *kvm;
	struct kvm_kpic_state pics[2]; /* 0 is master pic, 1 is slave pic */
	irq_request_func *irq_request;
	void *irq_request_opaque;
	int output;		/* intr from master PIC */
	struct kvm_io_device dev;
	void (*ack_notifier)(void *opaque, int irq);
	unsigned long irq_states[16];
} kvm_pic_t;

extern struct kvm_pic *kvm_create_pic(struct kvm *kvm);
extern void kvm_destroy_pic(struct kvm *kvm);
extern int kvm_pic_read_irq(struct kvm *kvm);
extern void kvm_pic_update_irq(struct kvm_pic *s);
extern void kvm_pic_clear_isr_ack(struct kvm *kvm);

extern struct kvm_pic *pic_irqchip(struct kvm *kvm);
extern int irqchip_in_kernel(struct kvm *kvm);

extern void kvm_pic_reset(struct kvm_kpic_state *s);
extern void kvm_inject_pit_timer_irqs(struct kvm_vcpu *vcpu);

extern void kvm_inject_pending_timer_irqs(struct kvm_vcpu *);
extern void kvm_inject_apic_timer_irqs(struct kvm_vcpu *);
extern void kvm_apic_nmi_wd_deliver(struct kvm_vcpu *);

extern int pit_has_pending_timer(struct kvm_vcpu *);
extern int apic_has_pending_timer(struct kvm_vcpu *);

#endif
