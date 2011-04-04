#ifndef __KVM_COALESCED_MMIO_H__
#define __KVM_COALESCED_MMIO_H__

/*
 * KVM coalesced MMIO
 *
 * Copyright (c) 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 */

struct kvm_coalesced_mmio_zone {
	uint64_t addr;
	uint32_t size;
	uint32_t pad;
};

struct kvm_coalesced_mmio_zone_ioc {
	struct kvm_coalesced_mmio_zone zone;
	int kvmid;
};

#ifdef CONFIG_KVM_MMIO

#define KVM_COALESCED_MMIO_ZONE_MAX 100

/* for KVM_REGISTER_COALESCED_MMIO / KVM_UNREGISTER_COALESCED_MMIO */


#ifdef _KERNEL

struct kvm_coalesced_mmio_dev {
	struct kvm_io_device dev;
	struct kvm *kvm;
	kmutex_t lock;
	int nb_zones;
	struct kvm_coalesced_mmio_zone zone[KVM_COALESCED_MMIO_ZONE_MAX];
};

int kvm_coalesced_mmio_init(struct kvm *kvm);
void kvm_coalesced_mmio_free(struct kvm *kvm);
int kvm_vm_ioctl_register_coalesced_mmio(struct kvm *kvm,
                                       struct kvm_coalesced_mmio_zone *zone);
int kvm_vm_ioctl_unregister_coalesced_mmio(struct kvm *kvm,
                                         struct kvm_coalesced_mmio_zone *zone);
#endif /*_KERNEL*/

#else

static int kvm_coalesced_mmio_init(struct kvm *kvm) { return 0; }
static void kvm_coalesced_mmio_free(struct kvm *kvm) { }

#endif

#endif
