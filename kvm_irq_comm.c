/*
 * irq_comm.c: Common API for in kernel interrupt controller
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
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

#include <sys/mutex.h>
#include <sys/sysmacros.h>

#include "kvm_bitops.h"
#include "kvm_apicdef.h"
#include "kvm_msidef.h"
#include "kvm_host.h"
#include "kvm_irq.h"
#include "kvm_ioapic.h"

static int
kvm_irq_line_state(unsigned long *irq_state, int irq_source_id, int level)
{
	/* Logical OR for level trig interrupt */
	if (level) {
		set_bit(irq_source_id, irq_state);
	} else {
		clear_bit(irq_source_id, irq_state);
	}

	return (!!(*irq_state));
}

static int
kvm_set_pic_irq(struct kvm_kernel_irq_routing_entry *e,
    struct kvm *kvm, int irq_source_id, int level)
{
	struct kvm_pic *pic = pic_irqchip(kvm);
	level = kvm_irq_line_state(&pic->irq_states[e->irqchip.pin],
	    irq_source_id, level);
	return (kvm_pic_set_irq(pic, e->irqchip.pin, level));
}

static int
kvm_set_ioapic_irq(struct kvm_kernel_irq_routing_entry *e,
    struct kvm *kvm, int irq_source_id, int level)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;
	level = kvm_irq_line_state(&ioapic->irq_states[e->irqchip.pin],
	    irq_source_id, level);

	return (kvm_ioapic_set_irq(ioapic, e->irqchip.pin, level));
}

static int
kvm_is_dm_lowest_prio(struct kvm_lapic_irq *irq)
{
	return (irq->delivery_mode == APIC_DM_LOWEST);
}

int
kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
    struct kvm_lapic_irq *irq)
{
	int i, r = -1;
	struct kvm_vcpu *vcpu, *lowest = NULL;

	if (irq->dest_mode == 0 && irq->dest_id == 0xff &&
	    kvm_is_dm_lowest_prio(irq))
		cmn_err(CE_CONT,
		    "!kvm: apic: phys broadcast and lowest prio\n");

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_apic_present(vcpu))
			continue;

		if (!kvm_apic_match_dest(vcpu, src, irq->shorthand,
		    irq->dest_id, irq->dest_mode))
			continue;

		if (!kvm_is_dm_lowest_prio(irq)) {
			if (r < 0)
				r = 0;
			r += kvm_apic_set_irq(vcpu, irq);
		} else {
			if (!lowest)
				lowest = vcpu;
			else if (kvm_apic_compare_prio(vcpu, lowest) < 0)
				lowest = vcpu;
		}
	}
	if (lowest)
		r = kvm_apic_set_irq(lowest, irq);

	return (r);
}

static int
kvm_set_msi(struct kvm_kernel_irq_routing_entry *e, struct kvm *kvm,
    int irq_source_id, int level)
{
	struct kvm_lapic_irq irq;

	if (!level)
		return (-1);

	KVM_TRACE2(msi__set__irq, uintptr_t, e->msi.address_lo,
	    uintptr_t, e->msi.data);

	irq.dest_id = (e->msi.address_lo & MSI_ADDR_DEST_ID_MASK) >>
	    MSI_ADDR_DEST_ID_SHIFT;
	irq.vector = (e->msi.data & MSI_DATA_VECTOR_MASK) >>
	    MSI_DATA_VECTOR_SHIFT;
	irq.dest_mode = (1 << MSI_ADDR_DEST_MODE_SHIFT) & e->msi.address_lo;
	irq.trig_mode = (1 << MSI_DATA_TRIGGER_SHIFT) & e->msi.data;
	irq.delivery_mode = e->msi.data & 0x700;
	irq.level = 1;
	irq.shorthand = 0;

	/* TODO Deal with RH bit of MSI message address */
	return (kvm_irq_delivery_to_apic(kvm, NULL, &irq));
}

/*
 * Return value:
 *  < 0   Interrupt was ignored (masked or not delivered for other reasons)
 *  = 0   Interrupt was coalesced (previous irq is still pending)
 *  > 0   Number of CPUs interrupt was delivered to
 */
int
kvm_set_irq(struct kvm *kvm, int irq_source_id, uint32_t irq, int level)
{
	struct kvm_kernel_irq_routing_entry *e, irq_set[KVM_NR_IRQCHIPS];
	int ret = -1, i = 0;
	struct kvm_irq_routing_table *irq_rt;

	/*
	 * Not possible to detect if the guest uses the PIC or the
	 * IOAPIC.  So set the bit in both. The guest will ignore
	 * writes to the unused one.
	 */
	mutex_enter(&kvm->irq_lock);
	irq_rt = kvm->irq_routing;
	if (irq < irq_rt->nr_rt_entries) {
		for (e = list_head(&irq_rt->map[irq]); e != NULL;
		    e = list_next(&irq_rt->map[irq], e)) {
			irq_set[i++] = *e;
		}
	}
	mutex_exit(&kvm->irq_lock);

	while (i--) {
		int r;
		r = irq_set[i].set(&irq_set[i], kvm, irq_source_id, level);
		if (r < 0)
			continue;

		ret = r + ((ret < 0) ? 0 : ret);
	}

	return (ret);
}

void
kvm_notify_acked_irq(struct kvm *kvm, unsigned irqchip, unsigned pin)
{
	struct kvm_irq_ack_notifier *kian;
	struct hlist_node *n;
	int gsi;

	KVM_TRACE2(ack__irq, unsigned int, irqchip, unsigned int, pin);

	mutex_enter(&kvm->irq_lock);
	gsi = (kvm->irq_routing)->chip[irqchip][pin];

	if (gsi != -1) {
		for (kian = list_head(&kvm->irq_ack_notifier_list);
		    kian != NULL;
		    kian = list_next(&kvm->irq_ack_notifier_list, kian)) {
			if (kian->gsi == gsi)
				kian->irq_acked(kian);
		}
	}
	mutex_exit(&kvm->irq_lock);
}

void
kvm_register_irq_ack_notifier(struct kvm *kvm,
    struct kvm_irq_ack_notifier *kian)
{
	mutex_enter(&kvm->irq_lock);
	list_insert_head(&kvm->irq_ack_notifier_list, kian);
	mutex_exit(&kvm->irq_lock);
}

void
kvm_unregister_irq_ack_notifier(struct kvm *kvm,
    struct kvm_irq_ack_notifier *kian)
{
	mutex_enter(&kvm->irq_lock);
	list_remove(&kvm->irq_ack_notifier_list, kian);
	mutex_exit(&kvm->irq_lock);
}

int
kvm_request_irq_source_id(struct kvm *kvm)
{
	unsigned long *bitmap = &kvm->arch.irq_sources_bitmap;
	int irq_source_id;

	mutex_enter(&kvm->irq_lock);
	irq_source_id = find_first_zero_bit(bitmap, 64);

	if (irq_source_id >= 64) {
		irq_source_id = -EFAULT;
		goto unlock;
	}

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);
	set_bit(irq_source_id, bitmap);
unlock:
	mutex_exit(&kvm->irq_lock);

	return (irq_source_id);
}

void
kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id)
{
	int i;

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);

	mutex_enter(&kvm->irq_lock);

	if (irq_source_id < 0 || irq_source_id >= BITS_PER_LONG)
		goto unlock;

	clear_bit(irq_source_id, &kvm->arch.irq_sources_bitmap);
	if (!irqchip_in_kernel(kvm))
		goto unlock;

	for (i = 0; i < KVM_IOAPIC_NUM_PINS; i++) {
		clear_bit(irq_source_id, &kvm->arch.vioapic->irq_states[i]);
		if (i >= 16)
			continue;
		clear_bit(irq_source_id, &pic_irqchip(kvm)->irq_states[i]);
	}
unlock:
	mutex_exit(&kvm->irq_lock);
}

void
kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
    struct kvm_irq_mask_notifier *kimn)
{
	mutex_enter(&kvm->irq_lock);
	kimn->irq = irq;
	list_insert_head(&kvm->mask_notifier_list, kimn);
	mutex_exit(&kvm->irq_lock);
}

void
kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
    struct kvm_irq_mask_notifier *kimn)
{
	mutex_enter(&kvm->irq_lock);
	list_remove(&kvm->mask_notifier_list, kimn);
	mutex_exit(&kvm->irq_lock);
}

void
kvm_fire_mask_notifiers(struct kvm *kvm, int irq, int mask)
{
	struct kvm_irq_mask_notifier *kimn;

	mutex_enter(&kvm->irq_lock);
	for (kimn = list_head(&kvm->mask_notifier_list); kimn != NULL;
	    kimn = list_next(&kvm->mask_notifier_list, kimn)) {
		if (kimn->irq == irq)
			kimn->func(kimn, mask);
	}

	mutex_exit(&kvm->irq_lock);
}

static int
setup_routing_entry(struct kvm_irq_routing_table *rt,
    struct kvm_kernel_irq_routing_entry *e,
    const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;
	int delta;
	unsigned max_pin;
	struct kvm_kernel_irq_routing_entry *ei;

	/*
	 * Do not allow GSI to be mapped to the same irqchip more than once.
	 * Allow only one to one mapping between GSI and MSI.
	 */
	for (ei = list_head(&rt->map[ue->gsi]); ei != NULL;
	    ei = list_next(&rt->map[ue->gsi], ei)) {
		if (ei->type == KVM_IRQ_ROUTING_MSI ||
		    ue->u.irqchip.irqchip == ei->irqchip.irqchip)
			return (r);
	}

	e->gsi = ue->gsi;
	e->type = ue->type;
	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		delta = 0;
		switch (ue->u.irqchip.irqchip) {
		case KVM_IRQCHIP_PIC_MASTER:
			e->set = kvm_set_pic_irq;
			max_pin = 16;
			break;
		case KVM_IRQCHIP_PIC_SLAVE:
			e->set = kvm_set_pic_irq;
			max_pin = 16;
			delta = 8;
			break;
		case KVM_IRQCHIP_IOAPIC:
			max_pin = KVM_IOAPIC_NUM_PINS;
			e->set = kvm_set_ioapic_irq;
			break;
		default:
			goto out;
		}
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin + delta;
		if (e->irqchip.pin >= max_pin)
			goto out;
		rt->chip[ue->u.irqchip.irqchip][e->irqchip.pin] = ue->gsi;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		break;
	default:
		goto out;
	}

	list_insert_head(&rt->map[e->gsi], e);
	r = 0;
out:
	return (r);
}

/*
 * Called only during vm destruction. Nobody can use the pointer at this stage
 */
void
kvm_free_irq_routing(struct kvm *kvm)
{
	if (kvm->irq_routing == NULL)
		return;

	kmem_free(kvm->irq_routing->rt_entries, kvm->irq_routing_sz);
	kmem_free(kvm->irq_routing, sizeof (struct kvm_irq_routing_table));
}

int
kvm_set_irq_routing(struct kvm *kvm, const struct kvm_irq_routing_entry *ue,
    unsigned nr, unsigned flags)
{
	struct kvm_irq_routing_table *new, *old;
	uint32_t i, j, nr_rt_entries = 0;
	size_t sz = sizeof (struct kvm_kernel_irq_routing_entry);
	size_t newsz, oldsz;
	int r;

	for (i = 0; i < nr; ++i) {
		if (ue[i].gsi >= KVM_MAX_IRQ_ROUTES)
			return (-EINVAL);
		nr_rt_entries = MAX(nr_rt_entries, ue[i].gsi);
	}

	nr_rt_entries += 1;

	new = kmem_zalloc(sizeof (*new), KM_SLEEP);

	for (i = 0; i < KVM_MAX_IRQ_ROUTES; i++) {
		list_create(&new->map[i], sz,
		    offsetof(struct kvm_kernel_irq_routing_entry, link));
	}

	new->rt_entries = kmem_zalloc(sz * nr, KM_SLEEP);
	newsz = sz * nr;

	new->nr_rt_entries = nr_rt_entries;
	for (i = 0; i < 3; i++)
		for (j = 0; j < KVM_IOAPIC_NUM_PINS; j++)
			new->chip[i][j] = -1;

	for (i = 0; i < nr; ++i) {
		r = -EINVAL;
		if (ue->flags)
			goto out;
		r = setup_routing_entry(new,
		    (struct kvm_kernel_irq_routing_entry *)
		    ((caddr_t)new->rt_entries + (i * sz)), ue);

		if (r)
			goto out;
		++ue;
	}

	mutex_enter(&kvm->irq_lock);
	old = kvm->irq_routing;
	oldsz = kvm->irq_routing_sz;
	kvm->irq_routing = new;
	kvm->irq_routing_sz = newsz;
	mutex_exit(&kvm->irq_lock);

	new = old;
	newsz = oldsz;
	r = 0;

out:
	if (new) {
		if (new->rt_entries != NULL)
			kmem_free(new->rt_entries, newsz);

		kmem_free(new, sizeof (*new));
	}
	return (r);
}

#define	IOAPIC_ROUTING_ENTRY(irq)				\
	{							\
		.gsi = irq,					\
		.type = KVM_IRQ_ROUTING_IRQCHIP,		\
		.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC,	\
		.u.irqchip.pin = (irq)				\
	}

#define	ROUTING_ENTRY1(irq) IOAPIC_ROUTING_ENTRY(irq)

#define	PIC_ROUTING_ENTRY(irq)					\
	{							\
		.gsi = irq,					\
		.type = KVM_IRQ_ROUTING_IRQCHIP,		\
		.u.irqchip.irqchip = SELECT_PIC(irq),		\
		.u.irqchip.pin = (irq) % 8			\
	}

#define	ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq), PIC_ROUTING_ENTRY(irq)

static const struct kvm_irq_routing_entry default_routing[] = {
	ROUTING_ENTRY2(0), ROUTING_ENTRY2(1),
	ROUTING_ENTRY2(2), ROUTING_ENTRY2(3),
	ROUTING_ENTRY2(4), ROUTING_ENTRY2(5),
	ROUTING_ENTRY2(6), ROUTING_ENTRY2(7),
	ROUTING_ENTRY2(8), ROUTING_ENTRY2(9),
	ROUTING_ENTRY2(10), ROUTING_ENTRY2(11),
	ROUTING_ENTRY2(12), ROUTING_ENTRY2(13),
	ROUTING_ENTRY2(14), ROUTING_ENTRY2(15),
	ROUTING_ENTRY1(16), ROUTING_ENTRY1(17),
	ROUTING_ENTRY1(18), ROUTING_ENTRY1(19),
	ROUTING_ENTRY1(20), ROUTING_ENTRY1(21),
	ROUTING_ENTRY1(22), ROUTING_ENTRY1(23),
};

int
kvm_setup_default_irq_routing(struct kvm *kvm)
{
	return (kvm_set_irq_routing(kvm, default_routing,
	    ARRAY_SIZE(default_routing), 0));
}
