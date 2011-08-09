/*
 * KVM coalesced MMIO
 *
 * Copyright (c) 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#include "kvm_host.h"
#include "kvm_coalesced_mmio.h"

static struct kvm_coalesced_mmio_dev *
to_mmio(struct kvm_io_device *dev)
{
	uintptr_t dp = (uintptr_t)dev;
	return ((struct kvm_coalesced_mmio_dev *)(dp -
	    offsetof(struct kvm_coalesced_mmio_dev, dev)));
}

static int
coalesced_mmio_in_range(struct kvm_coalesced_mmio_dev *dev, gpa_t addr, int len)
{
	struct kvm_coalesced_mmio_zone *zone;
	struct kvm_coalesced_mmio_ring *ring;
	unsigned avail;
	int i;

	/* Are we able to batch it ? */

	/*
	 * last is the first free entry
	 * check if we don't meet the first used entry
	 * there is always one unused entry in the buffer
	 */
	ring = dev->kvm->coalesced_mmio_ring;
	avail = (ring->first - ring->last - 1) % KVM_COALESCED_MMIO_MAX;
	if (avail < KVM_MAX_VCPUS) {
		/* full */
		return (0);
	}

	/* is it in a batchable area ? */

	for (i = 0; i < dev->nb_zones; i++) {
		zone = &dev->zone[i];

		/*
		 * (addr,len) is fully included in (zone->addr, zone->size)
		 */
		if (zone->addr <= addr && addr + len <= zone->addr + zone->size)
			return (1);
	}
	return (0);
}

static int
coalesced_mmio_write(struct kvm_io_device *this, gpa_t addr,
    int len, const void *val)
{
	struct kvm_coalesced_mmio_dev *dev = to_mmio(this);
	struct kvm_coalesced_mmio_ring *ring = dev->kvm->coalesced_mmio_ring;
	if (!coalesced_mmio_in_range(dev, addr, len))
		return (-EOPNOTSUPP);

	mutex_enter(&dev->lock);

	/* copy data in first free entry of the ring */

	ring->coalesced_mmio[ring->last].phys_addr = addr;
	ring->coalesced_mmio[ring->last].len = len;
	memcpy(ring->coalesced_mmio[ring->last].data, val, len);

	smp_wmb();
	ring->last = (ring->last + 1) % KVM_COALESCED_MMIO_MAX;
	mutex_exit(&dev->lock);
	return (0);
}

/*
 * We used to free the struct that contained us. We don't do that any more. It's
 * just wrong in this case.
 */
static void
coalesced_mmio_destructor(struct kvm_io_device *this)
{

}

static const struct kvm_io_device_ops coalesced_mmio_ops = {
	.write		= coalesced_mmio_write,
	.destructor	= coalesced_mmio_destructor,
};

int
kvm_coalesced_mmio_init(struct kvm *kvm)
{
	struct kvm_coalesced_mmio_dev *dev;
	page_t *page;
	int ret;

	kvm->coalesced_mmio_ring =
	    ddi_umem_alloc(PAGESIZE, DDI_UMEM_SLEEP, &kvm->mmio_cookie);

	ret = -ENOMEM;
	dev = kmem_zalloc(sizeof (struct kvm_coalesced_mmio_dev), KM_SLEEP);

	mutex_init(&dev->lock, NULL, MUTEX_DRIVER, 0);
	kvm_iodevice_init(&dev->dev, &coalesced_mmio_ops);
	dev->kvm = kvm;
	kvm->coalesced_mmio_dev = dev;

	mutex_enter(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, &dev->dev);
	mutex_exit(&kvm->slots_lock);
	if (ret < 0)
		goto out_free_dev;

	return (ret);

out_free_dev:
	kmem_free(dev, sizeof (struct kvm_coalesced_mmio_dev));
	ddi_umem_free(kvm->mmio_cookie);
	return (ret);
}

void
kvm_coalesced_mmio_free(struct kvm *kvmp)
{
	struct kvm_coalesced_mmio_dev *dev = kvmp->coalesced_mmio_dev;
	mutex_destroy(&dev->lock);
	mutex_enter(&kvmp->slots_lock);
	kvm_io_bus_unregister_dev(kvmp, KVM_MMIO_BUS, &dev->dev);
	mutex_exit(&kvmp->slots_lock);
	kvm_iodevice_destructor(&dev->dev);
	kmem_free(dev, sizeof (struct kvm_coalesced_mmio_dev));
	if (kvmp->coalesced_mmio_ring)
		ddi_umem_free(kvmp->mmio_cookie);
}

int
kvm_vm_ioctl_register_coalesced_mmio(struct kvm *kvm,
    struct kvm_coalesced_mmio_zone *zone)
{
	struct kvm_coalesced_mmio_dev *dev = kvm->coalesced_mmio_dev;

	if (dev == NULL)
		return (-EINVAL);

	mutex_enter(&kvm->slots_lock);
	if (dev->nb_zones >= KVM_COALESCED_MMIO_ZONE_MAX) {
		mutex_exit(&kvm->slots_lock);
		return (-ENOBUFS);
	}

	bcopy(zone, &dev->zone[dev->nb_zones],
	    sizeof (struct kvm_coalesced_mmio_zone));
	dev->nb_zones++;

	mutex_exit(&kvm->slots_lock);
	return (0);
}

int
kvm_vm_ioctl_unregister_coalesced_mmio(struct kvm *kvm,
    struct kvm_coalesced_mmio_zone *zone)
{
	int i;
	struct kvm_coalesced_mmio_dev *dev = kvm->coalesced_mmio_dev;
	struct kvm_coalesced_mmio_zone *z;

	if (dev == NULL)
		return (-EINVAL);

	mutex_enter(&kvm->slots_lock);

	i = dev->nb_zones;
	while (i) {
		z = &dev->zone[i - 1];

		/*
		 * Unregister all zones included in (zone->addr, zone->size)
		 */
		if (zone->addr <= z->addr &&
		    z->addr + z->size <= zone->addr + zone->size) {
			dev->nb_zones--;
			*z = dev->zone[dev->nb_zones];
		}
		i--;
	}

	mutex_exit(&kvm->slots_lock);

	return (0);
}
