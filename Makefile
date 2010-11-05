#
# Copyright (c) 2010 Joyent Inc., All Rights Reserved.
#

# Use the gcc compiler and Sun linker.
KERNEL_SOURCE=/wd320/max/onnv.121
CC=gcc -m64 -mcmodel=kernel
LD=/usr/bin/ld
CTFCONVERT=$(KERNEL_SOURCE)/usr/src/tools/proto/opt/onbld/bin/i386/ctfconvert
CTFMERGE=$(KERNEL_SOURCE)/usr/src/tools/proto/opt/onbld/bin/i386/ctfmerge

CFLAGS += -D_KERNEL -D_MACHDEP -Dx86 -DCONFIG_X86_64 -DDEBUG -c -O -g
INCLUDEDIR= -I $(KERNEL_SOURCE)/usr/src/uts/intel -I $(KERNEL_SOURCE)/usr/src/uts/i86pc

kvm: kvm.c kvm_x86.c kvm.h
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_x86.c
	$(CTFCONVERT) -i -L VERSION kvm.o
	$(CTFCONVERT) -i -L VERSION kvm_x86.o
	$(LD) -r -o kvm kvm.o kvm_x86.o
	$(CTFMERGE) -L VERSION -o kvm kvm.o kvm_x86.o

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
# gcc -m64 -mcmodel=kernel -D_KERNEL -D_MACHDEP -Dx86 -DCONFIG_X86_64 -DDEBUG -c -O -g -I /wd320/max/onnv.121/usr/src/uts/intel -I /wd320/max/onnv.121/usr/src/uts/i86pc kvm.c
# gcc -m64 -mcmodel=kernel -D_KERNEL -D_MACHDEP -Dx86 -DCONFIG_X86_64 -DDEBUG -c -O -g -I /wd320/max/onnv.121/usr/src/uts/intel -I /wd320/max/onnv.121/usr/src/uts/i86pc kvm_x86.c
