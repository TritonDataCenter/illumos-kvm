#ifndef __KVM_I8254_H
#define __KVM_I8254_H

/* XXX Our header files suck */
struct kvm;

void kvm_free_pit(struct kvm *);
struct kvm_pit *kvm_create_pit(struct kvm *kvm, uint32_t flags);
void kvm_pit_load_count(struct kvm *kvm, int channel, uint32_t val,
    boolean_t hpet_legacy_start);

#endif
