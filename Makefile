#
# Copyright (c) 2010 Joyent Inc., All Rights Reserved.
#

# Use the gcc compiler and Sun linker.
KERNEL_SOURCE=/wd320/max/onnv.121
CC=gcc -m64 -mcmodel=kernel
LD=/usr/bin/ld
CTFCONVERT=$(KERNEL_SOURCE)/usr/src/tools/proto/opt/onbld/bin/i386/ctfconvert
CTFMERGE=$(KERNEL_SOURCE)/usr/src/tools/proto/opt/onbld/bin/i386/ctfmerge

CFLAGS += -D_KERNEL -D_MACHDEP -Dx86 -DCONFIG_X86_64 -DDEBUG -c -g -DCONFIG_SOLARIS -DCONFIG_KVM_MMIO -O2 -fident -finline -fno-inline-functions -fno-builtin -fno-asm -nodefaultlibs -D__sun -O -D_ASM_INLINES -ffreestanding -Wall -Wno-unknown-pragmas -Wno-missing-braces -Wno-sign-compare -Wno-parentheses -Wno-uninitialized -Wno-implicit-function-declaration -Wno-unused -Wno-trigraphs -Wno-char-subscripts -Wno-switch -gdwarf-2 -std=gnu99 -fno-dwarf2-indirect-strings -Werror -DDIS_MEM -D_KERNEL -ffreestanding -D_SYSCALL32 -D_DDI_STRICT -Di86pc -D_MACHDEP -DOPTERON_ERRATUM_88 -DOPTERON_ERRATUM_91 -DOPTERON_ERRATUM_93 -DOPTERON_ERRATUM_95 -DOPTERON_ERRATUM_99 -DOPTERON_ERRATUM_100 -DOPTERON_ERRATUM_101 -DOPTERON_ERRATUM_108 -DOPTERON_ERRATUM_109 -DOPTERON_ERRATUM_121 -DOPTERON_ERRATUM_122 -DOPTERON_ERRATUM_123 -DOPTERON_ERRATUM_131 -DOPTERON_WORKAROUND_6336786 -DOPTERON_WORKAROUND_6323525 -DOPTERON_ERRATUM_172 -DOPTERON_ERRATUM_298 -I/wd320/max/onnv.121/usr/src/common -nostdinc -c -DUTS_RELEASE="5.11" -DUTS_VERSION="onnv.121" -DUTS_PLATFORM="i86pc" -mno-red-zone

INCLUDEDIR= -I $(KERNEL_SOURCE)/usr/src/uts/intel -I $(KERNEL_SOURCE)/usr/src/uts/i86pc -I $(KERNEL_SOURCE)/usr/src/uts/common

kvm: kvm.c kvm_x86.c emulate.c kvm.h kvm_x86host.h
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_x86.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) emulate.c
	$(CTFCONVERT) -i -L VERSION kvm.o
	$(CTFCONVERT) -i -L VERSION kvm_x86.o
	$(CTFCONVERT) -i -L VERSION emulate.o
	$(LD) -r -o kvm kvm.o kvm_x86.o emulate.o
	$(CTFMERGE) -L VERSION -o kvm kvm.o kvm_x86.o emulate.o

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
