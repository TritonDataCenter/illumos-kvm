#ifndef __KVM_I8254_H
#define __KVM_I8254_H

/* XXX Our header files suck */
struct kvm;

void kvm_free_pit(struct kvm *);

#endif
