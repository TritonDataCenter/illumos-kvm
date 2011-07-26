#
# Copyright (c) 2010 Joyent Inc., All Rights Reserved.
#

# Use the gcc compiler and Sun linker.
KERNEL_SOURCE=$(PWD)/../../illumos
PROTO_AREA=$(PWD)/../../../proto
CC=gcc -m64 -mcmodel=kernel
LD=/usr/bin/ld
CTFBINDIR=$(KERNEL_SOURCE)/usr/src/tools/proto/*/opt/onbld/bin/i386
CTFCONVERT=$(CTFBINDIR)/ctfconvert
CTFMERGE=$(CTFBINDIR)/ctfmerge
DESTDIR=
CFLAGS += -D_KERNEL -D_MACHDEP -Dx86 -DDEBUG -c -g -DCONFIG_SOLARIS -O2 -fident -fno-inline -fno-inline-functions -fno-builtin -fno-asm -nodefaultlibs -D__sun -O -D_ASM_INLINES -ffreestanding -Wall -Wno-unknown-pragmas -Wpointer-arith -Wno-unused -gdwarf-2 -std=gnu99 -fno-dwarf2-indirect-strings -Werror -DDIS_MEM -D_KERNEL -ffreestanding -D_SYSCALL32 -D_DDI_STRICT -Di86pc -D_MACHDEP -DOPTERON_ERRATUM_88 -DOPTERON_ERRATUM_91 -DOPTERON_ERRATUM_93 -DOPTERON_ERRATUM_95 -DOPTERON_ERRATUM_99 -DOPTERON_ERRATUM_100 -DOPTERON_ERRATUM_101 -DOPTERON_ERRATUM_108 -DOPTERON_ERRATUM_109 -DOPTERON_ERRATUM_121 -DOPTERON_ERRATUM_122 -DOPTERON_ERRATUM_123 -DOPTERON_ERRATUM_131 -DOPTERON_WORKAROUND_6336786 -DOPTERON_WORKAROUND_6323525 -DOPTERON_ERRATUM_172 -DOPTERON_ERRATUM_298 -I$(KERNEL_SOURCE)/usr/src/uts/common -nostdinc -c -DUTS_RELEASE="5.11" -DUTS_VERSION="joyent.147" -DUTS_PLATFORM="i86pc" -mno-red-zone

INCLUDEDIR= -I $(KERNEL_SOURCE)/usr/src/uts/intel -I $(KERNEL_SOURCE)/usr/src/uts/i86pc -I $(KERNEL_SOURCE)/usr/src/uts/common
CSTYLE=$(KERNEL_SOURCE)/usr/src/tools/scripts/cstyle
HDRCHK=tools/hdrchk
HDRCHK_USRFLAG="gcc"
HDRCHK_SYSFLAG="gcc -D_KERNEL"

all: kvm kvm.so JOY_kvm_link.so

HEADERS=			\
	kvm.h			\
	kvm_bitops.h		\
	kvm_cache_regs.h	\
	kvm_coalesced_mmio.h	\
	kvm_cpuid.h		\
	kvm_emulate.h		\
	kvm_host.h		\
	kvm_i8254.h		\
	kvm_impl.h		\
	kvm_ioapic.h		\
	kvm_iodev.h		\
	kvm_irq.h		\
	kvm_lapic.h		\
	kvm_mmu.h		\
	kvm_msidef.h		\
	kvm_paging_tmpl.h	\
	kvm_timer.h		\
	kvm_tss.h		\
	kvm_types.h		\
	kvm_vmx.h		\
	kvm_x86host.h		\
	kvm_x86impl.h		\
	kvm_x86.h

HDRCHK_USRHDRS= 		\
	kvm.h			\
	kvm_types.h		\
	kvm_x86.h

HDRCHK_SYSHDRS=			\
	kvm_bitops.h		\
	kvm_cache_regs.h	\
	kvm_cpuid.h		\
	kvm_host.h		\
	kvm_impl.h		\
	kvm_ioapic.h		\
	kvm_iodev.h		\
	kvm_irq.h		\
	kvm_msidef.h		\
	kvm_mmu.h		\
	kvm_timer.h		\
	kvm_tss.h		\
	kvm_types.h		\
	kvm_vmx.h		\
	kvm_x86host.h		\
	kvm_x86impl.h

kvm: kvm.c kvm_x86.c kvm_emulate.c kvm.h kvm_x86host.h msr.h kvm_bitops.h kvm_irq.c kvm_i8254.c kvm_lapic.c kvm_mmu.c kvm_iodev.c kvm_ioapic.c kvm_vmx.c kvm_i8259.c kvm_coalesced_mmio.c kvm_irq_comm.c kvm_cache_regs.c kvm_bitops.c $(HEADERS) 
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_x86.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_emulate.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_irq.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_i8254.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_lapic.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_mmu.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_iodev.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_ioapic.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_vmx.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_i8259.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_coalesced_mmio.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_irq_comm.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_cache_regs.c
	$(CC) $(CFLAGS) $(INCLUDEDIR) kvm_bitops.c
	$(CTFCONVERT) -i -L VERSION kvm.o
	$(CTFCONVERT) -i -L VERSION kvm_x86.o
	$(CTFCONVERT) -i -L VERSION kvm_emulate.o
	$(CTFCONVERT) -i -L VERSION kvm_irq.o
	$(CTFCONVERT) -i -L VERSION kvm_i8254.o
	$(CTFCONVERT) -i -L VERSION kvm_lapic.o
	$(CTFCONVERT) -i -L VERSION kvm_mmu.o
	$(CTFCONVERT) -i -L VERSION kvm_iodev.o
	$(CTFCONVERT) -i -L VERSION kvm_ioapic.o
	$(CTFCONVERT) -i -L VERSION kvm_vmx.o
	$(CTFCONVERT) -i -L VERSION kvm_i8259.o
	$(CTFCONVERT) -i -L VERSION kvm_coalesced_mmio.o
	$(CTFCONVERT) -i -L VERSION kvm_irq_comm.o
	$(CTFCONVERT) -i -L VERSION kvm_cache_regs.o
	$(CTFCONVERT) -i -L VERSION kvm_bitops.o
	$(LD) -r -o kvm kvm.o kvm_x86.o kvm_emulate.o kvm_irq.o kvm_i8254.o kvm_lapic.o kvm_mmu.o kvm_iodev.o kvm_ioapic.o kvm_vmx.o kvm_i8259.o kvm_coalesced_mmio.o kvm_irq_comm.o kvm_cache_regs.o kvm_bitops.o
	$(CTFMERGE) -L VERSION -o kvm kvm.o kvm_x86.o kvm_emulate.o kvm_irq.o kvm_i8254.o kvm_lapic.o kvm_mmu.o kvm_iodev.o kvm_ioapic.o kvm_vmx.o kvm_i8259.o kvm_coalesced_mmio.o kvm_irq_comm.o kvm_cache_regs.o kvm_bitops.o

kvm.so: kvm_mdb.c
	gcc -m64 -shared \
	    -fPIC $(CFLAGS) $(INCLUDEDIR) -I/usr/include -o $@ kvm_mdb.c

JOY_kvm_link.so: kvm_link.c
	/opt/SUNWspro/bin/cc -O -xspace -Xa  -xildoff -errtags=yes -errwarn=%all -erroff=E_EMPTY_TRANSLATION_UNIT -erroff=E_STATEMENT_NOT_REACHED -xc99=%none    -W0,-xglobalstatic -v -K pic -DTEXT_DOMAIN=\"SUNW_OST_OSCMD\" -D_TS_ERRNO -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT -I$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/ -I$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/../../uts/common -I$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/../modload -c -o  kvm_link.o kvm_link.c		
	/opt/SUNWspro/bin/cc -o JOY_kvm_link.so -G -ztext -zdefs -Bdirect -M$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/mapfile-vers -M$(KERNEL_SOURCE)/usr/src/common/mapfiles/common/map.pagealign -M$(KERNEL_SOURCE)/usr/src/common/mapfiles/common/map.noexdata -h JOY_kvm_link.so kvm_link.o -L$(PROTO_AREA)/lib -L$(PROTO_AREA)/usr/lib -ldevinfo -lc

install: kvm
	@echo "==> Installing kvm module (to $(DESTDIR)/)"
	@mkdir -p $(DESTDIR)/usr/kernel/drv/amd64
	@cp kvm $(DESTDIR)/usr/kernel/drv/amd64/kvm
	@cp kvm.conf $(DESTDIR)/usr/kernel/drv
	@mkdir -p $(DESTDIR)/usr/lib/mdb/kvm/amd64
	@cp kvm.so $(DESTDIR)/usr/lib/mdb/kvm/amd64
	@cp JOY_kvm_link.so $(DESTDIR)/usr/lib/devfsadm/linkmod

check:
	@$(CSTYLE) kvm.c kvm_mdb.c kvm_emulate.c kvm_x86.c kvm_irq.c kvm_lapic.c kvm_i8254.c kvm_mmu.c kvm_iodev.c kvm_ioapic.c kvm_vmx.c kvm_i8259.c kvm_coalesced_mmio.c kvm_irq_comm.c kvm_cache_regs.c kvm_bitops.c $(HEADERS) kvm_link.c
	@./tools/xxxcheck kvm_x86.c kvm.c kvm_irq.c kvm_lapic.c kvm_i8254.c kvm_mmu.c kvm_iodev.c kvm_ioapic.c kvm_vmx.c kvm_i8259.c kvm_coalesced_mmio.c kvm_irq_comm.c kvm_cache_regs.c kvm_bitops.c
	@$(HDRCHK) $(HDRCHK_USRFLAG) $(HDRCHK_USRHDRS)
	@$(HDRCHK) $(HDRCHK_SYSFLAG) $(HDRCHK_SYSHDRS)

clean:
	@pfexec rm -f *.o kvm kvm.so JOY_kvm_link.so

uninstall:
	@pfexec rem_drv kvm || /bin/true
	@pfexec rm -f /usr/kernel/drv/kvm* /usr/kernel/drv/amd64/kvm*
# gcc -m64 -mcmodel=kernel -D_KERNEL -D_MACHDEP -Dx86 -DCONFIG_X86_64 -DDEBUG -c -O -g -I /wd320/max/onnv.121/usr/src/uts/intel -I /wd320/max/onnv.121/usr/src/uts/i86pc kvm.c
# gcc -m64 -mcmodel=kernel -D_KERNEL -D_MACHDEP -Dx86 -DCONFIG_X86_64 -DDEBUG -c -O -g -I /wd320/max/onnv.121/usr/src/uts/intel -I /wd320/max/onnv.121/usr/src/uts/i86pc kvm_x86.c
