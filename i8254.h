#ifndef __I8254_H
#define __I8254_h

/* XXX Our header files suck */
struct kvm;

void kvm_free_pit(struct kvm *);

#endif
