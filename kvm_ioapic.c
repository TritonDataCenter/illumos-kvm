/*
 *  Copyright (C) 2001  MandrakeSoft S.A.
 *
 *    MandrakeSoft S.A.
 *    43, rue d'Aboukir
 *    75002 Paris - France
 *    http://www.linux-mandrake.com/
 *    http://www.mandrakesoft.com/
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *  Yunhong Jiang <yunhong.jiang@intel.com>
 *  Yaozu (Eddie) Dong <eddie.dong@intel.com>
 *  Based on Xen 3.1 code.
 *
 *  Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#include <sys/types.h>
#include <sys/mutex.h>

#include "kvm_bitops.h"
#include "kvm_host.h"
#include "kvm_timer.h"
#include "kvm_ioapic.h"
#include "kvm_lapic.h"
#include "kvm_irq.h"

static int ioapic_deliver(struct kvm_ioapic *, int);

struct kvm_ioapic *
ioapic_irqchip(struct kvm *kvm)
{
	return (kvm->arch.vioapic);
}

static unsigned long
ioapic_read_indirect(struct kvm_ioapic *ioapic,
    unsigned long addr, unsigned long length)
{
	unsigned long result = 0;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		result = ((((IOAPIC_NUM_PINS - 1) & 0xff) << 16) |
		    (IOAPIC_VERSION_ID & 0xff));
		break;

	case IOAPIC_REG_APIC_ID:
	case IOAPIC_REG_ARB_ID:
		result = ((ioapic->id & 0xf) << 24);
		break;

	default: {
		uint32_t redir_index = (ioapic->ioregsel - 0x10) >> 1;
		uint64_t redir_content;

		if (redir_index < IOAPIC_NUM_PINS) {
			redir_content = ioapic->redirtbl[redir_index].bits;
		} else {
			redir_content = ~0ULL;
		}
		result = (ioapic->ioregsel & 0x1) ?
		    (redir_content >> 32) & 0xffffffff :
		    redir_content & 0xffffffff;
		break;
	}
	}

	return (result);
}

static int
ioapic_service(struct kvm_ioapic *ioapic, unsigned int idx)
{
	union kvm_ioapic_redirect_entry *pent;
	int injected = -1;

	pent = &ioapic->redirtbl[idx];

	if (!pent->fields.mask) {
		injected = ioapic_deliver(ioapic, idx);
		if (injected && pent->fields.trig_mode == IOAPIC_LEVEL_TRIG)
			pent->fields.remote_irr = 1;
	}

	return (injected);
}

static void
update_handled_vectors(struct kvm_ioapic *ioapic)
{
	unsigned long handled_vectors[4];
	int i;

	memset(handled_vectors, 0, sizeof (handled_vectors));
	for (i = 0; i < IOAPIC_NUM_PINS; ++i)
		__set_bit(ioapic->redirtbl[i].fields.vector, handled_vectors);
	memcpy(ioapic->handled_vectors, handled_vectors,
	    sizeof (handled_vectors));

	smp_wmb();
}

static void
ioapic_write_indirect(struct kvm_ioapic *ioapic, uint32_t val)
{
	unsigned index;
	int mask_before, mask_after;
	union kvm_ioapic_redirect_entry *e;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		/* Writes are ignored. */
		break;

	case IOAPIC_REG_APIC_ID:
		ioapic->id = (val >> 24) & 0xf;
		break;

	case IOAPIC_REG_ARB_ID:
		break;

	default:
		index = (ioapic->ioregsel - 0x10) >> 1;

		if (index >= IOAPIC_NUM_PINS)
			return;

		e = &ioapic->redirtbl[index];
		mask_before = e->fields.mask;
		if (ioapic->ioregsel & 1) {
			e->bits &= 0xffffffff;
			e->bits |= (uint64_t) val << 32;
		} else {
			e->bits &= ~0xffffffffULL;
			e->bits |= (uint32_t) val;
			e->fields.remote_irr = 0;
		}

		update_handled_vectors(ioapic);
		mask_after = e->fields.mask;

		if (mask_before != mask_after)
			kvm_fire_mask_notifiers(ioapic->kvm, index, mask_after);

		if (e->fields.trig_mode == IOAPIC_LEVEL_TRIG &&
		    ioapic->irr & (1 << index))
			ioapic_service(ioapic, index);
		break;
	}
}

static int
ioapic_deliver(struct kvm_ioapic *ioapic, int irq)
{
	union kvm_ioapic_redirect_entry *entry = &ioapic->redirtbl[irq];
	struct kvm_lapic_irq irqe;

	irqe.dest_id = entry->fields.dest_id;
	irqe.vector = entry->fields.vector;
	irqe.dest_mode = entry->fields.dest_mode;
	irqe.trig_mode = entry->fields.trig_mode;
	irqe.delivery_mode = entry->fields.delivery_mode << 8;
	irqe.level = 1;
	irqe.shorthand = 0;

	/* Always delivery PIT interrupt to vcpu 0 */
	if (irq == 0) {
		irqe.dest_mode = 0; /* Physical mode. */
		/*
		 * need to read apic_id from apic regiest since
		 * it can be rewritten
		 */
		irqe.dest_id = ioapic->kvm->bsp_vcpu->vcpu_id;
	}

	return (kvm_irq_delivery_to_apic(ioapic->kvm, NULL, &irqe));
}

int
kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int level)
{
	uint32_t old_irr = ioapic->irr;
	uint32_t mask = 1 << irq;
	union kvm_ioapic_redirect_entry entry;
	int ret = 1;

	mutex_enter(&ioapic->lock);
	if (irq >= 0 && irq < IOAPIC_NUM_PINS) {
		entry = ioapic->redirtbl[irq];
		level ^= entry.fields.polarity;
		if (!level)
			ioapic->irr &= ~mask;
		else {
			int edge = (entry.fields.trig_mode == IOAPIC_EDGE_TRIG);
			ioapic->irr |= mask;
			if ((edge && old_irr != ioapic->irr) ||
			    (!edge && !entry.fields.remote_irr))
				ret = ioapic_service(ioapic, irq);
			else
				ret = 0; /* report coalesced interrupt */
		}

		KVM_TRACE3(ioapic__set__irq, uintptr_t, entry.bits,
		    int, irq, int, ret == 0);
	}
	mutex_exit(&ioapic->lock);

	return (ret);
}

static void
__kvm_ioapic_update_eoi(struct kvm_ioapic *ioapic, int vector, int trigger_mode)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++) {
		union kvm_ioapic_redirect_entry *ent = &ioapic->redirtbl[i];

		if (ent->fields.vector != vector)
			continue;

		/*
		 * We are dropping lock while calling ack notifiers because ack
		 * notifier callbacks for assigned devices call into IOAPIC
		 * recursively. Since remote_irr is cleared only after call
		 * to notifiers if the same vector will be delivered while lock
		 * is dropped it will be put into irr and will be delivered
		 * after ack notifier returns.
		 */
		mutex_exit(&ioapic->lock);
		kvm_notify_acked_irq(ioapic->kvm, KVM_IRQCHIP_IOAPIC, i);
		mutex_enter(&ioapic->lock);

		if (trigger_mode != IOAPIC_LEVEL_TRIG)
			continue;

		if (ent->fields.trig_mode != IOAPIC_LEVEL_TRIG) {
			/*
			 * If the same vector is being used for two different
			 * I/O redirection table entries with different trigger
			 * modes, our trigger mode and the trigger mode of
			 * the entry will differ for at least one entry.
			 * Most operating systems don't do this (that is, most
			 * do not reuse a vector for interrupts with different
			 * trigger modes), but FreeBSD (at least) is a notable
			 * exception:  it allocates vectors on a per-local APIC
			 * basis, and will therefore reuse the same vector for
			 * entirely different interrupt sources.  In this case,
			 * we need do nothing else, and simply continue.
			 */
			continue;
		}

		ent->fields.remote_irr = 0;
		if (!ent->fields.mask && (ioapic->irr & (1 << i)))
			ioapic_service(ioapic, i);
	}
}

void
kvm_ioapic_update_eoi(struct kvm *kvm, int vector, int trigger_mode)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;

	smp_rmb();

	if (!test_bit(vector, ioapic->handled_vectors))
		return;

	mutex_enter(&ioapic->lock);
	__kvm_ioapic_update_eoi(ioapic, vector, trigger_mode);
	mutex_exit(&ioapic->lock);
}

static struct kvm_ioapic *
to_ioapic(struct kvm_io_device *dev)
{
	return (struct kvm_ioapic *)(((caddr_t)dev) -
	    offsetof(struct kvm_ioapic, dev));
}

static int
ioapic_in_range(struct kvm_ioapic *ioapic, gpa_t addr)
{
	return ((addr >= ioapic->base_address &&
	    (addr < ioapic->base_address + IOAPIC_MEM_LENGTH)));
}

static int
ioapic_mmio_read(struct kvm_io_device *this, gpa_t addr, int len, void *val)
{
	struct kvm_ioapic *ioapic = to_ioapic(this);
	uint32_t result;

	if (!ioapic_in_range(ioapic, addr))
		return (-EOPNOTSUPP);

	ASSERT(!(addr & 0xf));	/* check alignment */

	addr &= 0xff;
	mutex_enter(&ioapic->lock);
	switch (addr) {
	case IOAPIC_REG_SELECT:
		result = ioapic->ioregsel;
		break;

	case IOAPIC_REG_WINDOW:
		result = ioapic_read_indirect(ioapic, addr, len);
		break;

	default:
		result = 0;
		break;
	}

	mutex_exit(&ioapic->lock);

	switch (len) {
	case 8:
		*(uint64_t *) val = result;
		break;
	case 1:
	case 2:
	case 4:
		memcpy(val, (char *)&result, len);
		break;
	default:
		cmn_err(CE_WARN, "ioapic: wrong length %d\n", len);
	}

	return (0);
}

static int
ioapic_mmio_write(struct kvm_io_device *this, gpa_t addr, int len,
    const void *val)
{
	struct kvm_ioapic *ioapic = to_ioapic(this);
	uint32_t data;

	if (!ioapic_in_range(ioapic, addr))
		return (-EOPNOTSUPP);

	ASSERT(!(addr & 0xf));	/* check alignment */

	if (len == 4 || len == 8)
		data = *(uint32_t *) val;
	else {
		return (0);
	}

	addr &= 0xff;
	mutex_enter(&ioapic->lock);
	switch (addr) {
	case IOAPIC_REG_SELECT:
		ioapic->ioregsel = data;
		break;

	case IOAPIC_REG_WINDOW:
		ioapic_write_indirect(ioapic, data);
		break;
	default:
		break;
	}
	mutex_exit(&ioapic->lock);
	return (0);
}

void
kvm_ioapic_reset(struct kvm_ioapic *ioapic)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++)
		ioapic->redirtbl[i].fields.mask = 1;

	ioapic->base_address = IOAPIC_DEFAULT_BASE_ADDRESS;
	ioapic->ioregsel = 0;
	ioapic->irr = 0;
	ioapic->id = 0;
	update_handled_vectors(ioapic);
}

static const struct kvm_io_device_ops ioapic_mmio_ops = {
	.read	= ioapic_mmio_read,
	.write	= ioapic_mmio_write,
};

int
kvm_ioapic_init(struct kvm *kvm)
{
	struct kvm_ioapic *ioapic;
	int ret;

	ioapic = kmem_zalloc(sizeof (struct kvm_ioapic), KM_SLEEP);
	mutex_init(&ioapic->lock, NULL, MUTEX_DRIVER, 0);
	kvm->arch.vioapic = ioapic;
	kvm_ioapic_reset(ioapic);
	kvm_iodevice_init(&ioapic->dev, &ioapic_mmio_ops);
	ioapic->kvm = kvm;
	mutex_enter(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, &ioapic->dev);
	mutex_exit(&kvm->slots_lock);

	if (ret < 0) {
		kvm->arch.vioapic = NULL;
		kmem_free(ioapic, sizeof (struct kvm_ioapic));
	}

	return (ret);
}

void
kvm_ioapic_destroy(struct kvm *kvm)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;

	if (ioapic) {
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &ioapic->dev);
		kvm->arch.vioapic = NULL;
		kmem_free(ioapic, sizeof (struct kvm_ioapic));
	}
}

int
kvm_get_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state)
{
	struct kvm_ioapic *ioapic = ioapic_irqchip(kvm);
	if (!ioapic)
		return (EINVAL);

	mutex_enter(&ioapic->lock);
	memcpy(state, ioapic, sizeof (struct kvm_ioapic_state));
	mutex_exit(&ioapic->lock);

	return (0);
}

int
kvm_set_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state)
{
	struct kvm_ioapic *ioapic = ioapic_irqchip(kvm);

	if (!ioapic)
		return (EINVAL);

	mutex_enter(&ioapic->lock);
	memcpy(ioapic, state, sizeof (struct kvm_ioapic_state));
	update_handled_vectors(ioapic);
	mutex_exit(&ioapic->lock);

	return (0);
}
