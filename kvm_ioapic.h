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
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#ifndef __KVM_IO_APIC_H
#define	__KVM_IO_APIC_H

#include "kvm_host.h"
#include "kvm_iodev.h"

struct kvm;
struct kvm_vcpu;

#define	IOAPIC_NUM_PINS  KVM_IOAPIC_NUM_PINS
#define	IOAPIC_VERSION_ID 0x11	/* IOAPIC version */
#define	IOAPIC_EDGE_TRIG  0
#define	IOAPIC_LEVEL_TRIG 1

#define	IOAPIC_DEFAULT_BASE_ADDRESS	0xfec00000
#define	IOAPIC_MEM_LENGTH	0x100

/* Direct registers. */
#define	IOAPIC_REG_SELECT	0x00
#define	IOAPIC_REG_WINDOW	0x10
#define	IOAPIC_REG_EOI		0x40	/* IA64 IOSAPIC only */

/* Indirect registers. */
#define	IOAPIC_REG_APIC_ID 0x00	/* x86 IOAPIC only */
#define	IOAPIC_REG_VERSION 0x01
#define	IOAPIC_REG_ARB_ID  0x02	/* x86 IOAPIC only */

/* ioapic delivery mode */
#define	IOAPIC_FIXED			0x0
#define	IOAPIC_LOWEST_PRIORITY		0x1
#define	IOAPIC_PMI			0x2
#define	IOAPIC_NMI			0x4
#define	IOAPIC_INIT			0x5
#define	IOAPIC_EXTINT			0x7

typedef struct kvm_ioapic {
	uint64_t base_address;
	uint32_t ioregsel;
	uint32_t id;
	uint32_t irr;
	uint32_t pad;
	union kvm_ioapic_redirect_entry redirtbl[IOAPIC_NUM_PINS];
	unsigned long irq_states[IOAPIC_NUM_PINS];
	struct kvm_io_device dev;
	struct kvm *kvm;
	void (*ack_notifier)(void *opaque, int irq);
	kmutex_t lock;
	unsigned long handled_vectors[BT_BITOUL(256)];
} kvm_ioapic_t;


extern struct kvm_ioapic *ioapic_irqchip(struct kvm *);
extern void kvm_ioapic_update_eoi(struct kvm *, int, int);
extern int kvm_ioapic_init(struct kvm *);
extern void kvm_ioapic_destroy(struct kvm *);
extern int kvm_ioapic_set_irq(struct kvm_ioapic *, int, int);
extern void kvm_ioapic_reset(struct kvm_ioapic *);
extern int kvm_irq_delivery_to_apic(struct kvm *, struct kvm_lapic *,
    struct kvm_lapic_irq *);
extern int kvm_get_ioapic(struct kvm *, struct kvm_ioapic_state *);
extern int kvm_set_ioapic(struct kvm *, struct kvm_ioapic_state *);

#endif
