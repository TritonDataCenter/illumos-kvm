#
# Copyright (c) 2010 Joyent Inc., All Rights Reserved.
#

# Use the Sun Studio compiler and Sun linker.
KERNEL_SOURCE=
CC=/opt/SUNWspro/bin/cc -xarch=sse2a -m64 -xmodel=kernel
LD=/usr/bin/ld
CFLAGS += -D_KERNEL -D_MACHDEP -Dx86 _DCONFIG_X86_64 -DDEBUG -c -O
INCLUDEDIR=$(KERNEL_SOURCE)/usr/src/uts/intel $(KERNEL_SOURCE)/usr/src/uts/i86pc

kvm: kvm.c kvm_x86.c kvm.h
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_x86.c
	$(LD) -r -o kvm kvm.o kvm_x86.o

install: kvm
	@echo "==> Installing kvm module"
	@pfexec cp kvm /tmp
	@pfexec ln -sf /tmp/kvm /usr/kernel/drv/amd64/kvm
	@pfexec cp kvm.conf /usr/kernel/drv

load: install
	@echo "==> Loading kvm module"
	@pfexec rem_drv kvm || /bin/true
	@pfexec add_drv -v -i 'kvm' -m '* 0660 root sys' -c kvm kvm
	@grep "^type=ddi_pseudo;name=kvm" /etc/devlink.tab >/dev/null \
        || printf "type=ddi_pseudo;name=kvm\t\\D\n" | pfexec tee -a /etc/devlink.tab >/dev/null
	@pfexec devfsadm -v -u

clean:
	@pfexec rm -vf *.o kvm

uninstall:
	@pfexec rem_drv kvm || /bin/true
	@pfexec rm -vf /usr/kernel/drv/kvm* /usr/kernel/drv/amd64/kvm*
