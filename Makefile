#
# Copyright 2020 Joyent, Inc.
#

include		$(PWD)/../../../build.env

KERNEL_SOURCE =	$(PWD)/../../illumos
MDB_SOURCE =	$(KERNEL_SOURCE)/usr/src/cmd/mdb
PROTO_AREA =	$(PWD)/../../../proto
STRAP_AREA =	$(PWD)/../../../proto.strap

CC =		$(STRAP_AREA)/usr/bin/gcc
LD =		/usr/bin/ld
CTFBINDIR =	$(KERNEL_SOURCE)/usr/src/tools/proto/*/opt/onbld/bin/i386
CTFCONVERT =	$(CTFBINDIR)/ctfconvert
CSTYLE =	$(KERNEL_SOURCE)/usr/src/tools/scripts/cstyle
HDRCHK =	tools/hdrchk
HDRCHK_USRFLAG =	"$(CC)"
HDRCHK_SYSFLAG =	"$(CC) -D_KERNEL"

ALWAYS_CPPFLAGS = \
	-D__sun

KERNEL_CPPFLAGS = \
	$(ALWAYS_CPPFLAGS) \
	-D_KERNEL \
	-D_MACHDEP \
	-Dx86 \
	-DDEBUG \
	-DCONFIG_SOLARIS \
	-D_ASM_INLINES \
	-DDIS_MEM \
	-D_KERNEL \
	-D_SYSCALL32 \
	-D_DDI_STRICT \
	-Di86pc \
	-D_MACHDEP \
	-DOPTERON_ERRATUM_88 \
	-DOPTERON_ERRATUM_91 \
	-DOPTERON_ERRATUM_93 \
	-DOPTERON_ERRATUM_95 \
	-DOPTERON_ERRATUM_99 \
	-DOPTERON_ERRATUM_100 \
	-DOPTERON_ERRATUM_101 \
	-DOPTERON_ERRATUM_108 \
	-DOPTERON_ERRATUM_109 \
	-DOPTERON_ERRATUM_121 \
	-DOPTERON_ERRATUM_122 \
	-DOPTERON_ERRATUM_123 \
	-DOPTERON_ERRATUM_131 \
	-DOPTERON_WORKAROUND_6336786 \
	-DOPTERON_WORKAROUND_6323525 \
	-DOPTERON_ERRATUM_172 \
	-DOPTERON_ERRATUM_298 \
	-DUTS_RELEASE="5.11" \
	-DUTS_VERSION="joyent.147" \
	-DUTS_PLATFORM="i86pc" \
	-nostdinc \
	-I$(KERNEL_SOURCE)/usr/src/uts/common \
	-I$(KERNEL_SOURCE)/usr/src/uts/intel \
	-I$(KERNEL_SOURCE)/usr/src/uts/i86pc

DMOD_CPPFLAGS = \
	$(ALWAYS_CPPFLAGS) \
	-D_KERNEL \
	-DTEXT_DOMAIN="SUNW_OST_OSCMD" \
	-D_TS_ERRNO \
	-D_ELF64 \
	-Ui386 \
	-U__i386 \
	-isystem $(PROTO_AREA)/usr/include \
	-I$(KERNEL_SOURCE)/usr/src/uts/common \
	-I$(KERNEL_SOURCE)/usr/src/uts/intel \
	-I$(KERNEL_SOURCE)/usr/src/uts/i86pc \
	-I$(MDB_SOURCE)/common

LINKMOD_CPPFLAGS = \
	$(ALWAYS_CPPFLAGS) \
	-DTEXT_DOMAIN="SUNW_OST_OSCMD" \
	-D_TS_ERRNO \
	-isystem $(PROTO_AREA)/usr/include \
	-I$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/ \
	-I$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/../../uts/common \
	-I$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/../modload

ALWAYS_CFLAGS = \
	-fident \
	-fno-builtin \
	-fno-asm \
	-nodefaultlibs \
	-Wall \
	-Wno-unknown-pragmas \
	-Wno-unused \
	-Werror \
	-fno-inline-functions

#
# Skip dangerous GCC options (not that any specific problems are know of here).
#
ifneq ($(PRIMARY_COMPILER_VER),4)
ALWAYS_CFLAGS += -fno-aggressive-loop-optimizations
endif

#
# Replacing -O with -O2 causes the KVM host to panic.  Don't do that.
#
KERNEL_CFLAGS = \
	$(ALWAYS_CFLAGS) \
	-m64 \
	-mcmodel=kernel \
	-g \
	-O \
	-fno-inline \
	-ffreestanding \
	-fno-strict-aliasing \
	-Wpointer-arith \
	-gdwarf-2 \
	-std=gnu99 \
	-mno-red-zone

#
# Fix fbt entry probes.
#
ifneq ($(PRIMARY_COMPILER_VER),4)
KERNEL_CFLAGS += \
	-fno-shrink-wrap \
	-mindirect-branch=thunk-extern \
	-mindirect-branch-register
endif

USER_CFLAGS = \
	-finline \
	-gdwarf-2 \
	-std=gnu89 \
	-Wno-missing-braces \
	-Wno-sign-compare \
	-Wno-parentheses \
	-Wno-uninitialized \
	-Wno-implicit-function-declaration \
	-Wno-trigraphs \
	-Wno-char-subscripts \
	-Wno-switch

DMOD_CFLAGS = \
	$(ALWAYS_CFLAGS) \
	$(USER_CFLAGS) \
	-m64 \
	-fno-strict-aliasing \
	-fno-unit-at-a-time \
	-fno-optimize-sibling-calls \
	-O2 \
	-fno-inline-small-functions \
	-fno-inline-functions-called-once \
	-mtune=opteron \
	-Wno-address \
	-ffreestanding \
	-fPIC

LINKMOD_CFLAGS = \
	$(ALWAYS_CFLAGS) \
	$(USER_CFLAGS) \
	-m32 \
	-O \
	-fpic

USER_LDFLAGS = \
	-Wl,-Bdirect \
	-Wl,-zfatal-warnings \
	-Wl,-zassert-deflib \
	-Wl,-zguidance

DMOD_LDFLAGS = \
	$(USER_LDFLAGS) \
	-m64 \
	-shared \
	-nodefaultlibs \
	-std=gnu89 \
	-Wl,-M$(KERNEL_SOURCE)/usr/src/common/mapfiles/common/map.pagealign \
	-Wl,-M$(KERNEL_SOURCE)/usr/src/common/mapfiles/common/map.noexdata \
	-Wl,-ztext \
	-Wl,-zdefs \
	-Wl,-zignore \
	-Wl,-M$(MDB_SOURCE)/common/modules/conf/mapfile-extern \
	-L$(PROTO_AREA)/lib/amd64 \
	-L$(PROTO_AREA)/usr/lib/amd64

DMOD_LIBS = \
	-lc

LINKMOD_LDFLAGS = \
	$(USER_LDFLAGS) \
	-shared \
	-nodefaultlibs \
	-Wl,-zdefs \
	-Wl,-ztext \
	-Wl,-M$(KERNEL_SOURCE)/usr/src/cmd/devfsadm/mapfile-vers \
	-Wl,-M$(KERNEL_SOURCE)/usr/src/common/mapfiles/common/map.pagealign \
	-Wl,-M$(KERNEL_SOURCE)/usr/src/common/mapfiles/common/map.noexdata \
	-h JOY_kvm_link.so \
	-L$(PROTO_AREA)/lib \
	-L$(PROTO_AREA)/usr/lib \

LINKMOD_LIBS = \
	-ldevinfo \
	-lc

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
	kvm_msr.h		\
	kvm_paging_tmpl.h	\
	kvm_timer.h		\
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
	kvm_types.h		\
	kvm_vmx.h		\
	kvm_x86host.h		\
	kvm_x86impl.h

KMOD_SRCS =			\
	kvm.c			\
	kvm_x86.c		\
	kvm_emulate.c		\
	kvm_irq.c		\
	kvm_i8254.c		\
	kvm_lapic.c		\
	kvm_mmu.c		\
	kvm_iodev.c		\
	kvm_ioapic.c		\
	kvm_vmx.c		\
	kvm_i8259.c		\
	kvm_coalesced_mmio.c	\
	kvm_irq_comm.c		\
	kvm_cache_regs.c

DMOD_SRCS = \
	kvm_mdb.c

LINKMOD_SRCS = \
	kvm_link.c

CSTYLE_CHK = \
	$(KMOD_SRCS:%=%.chk) \
	$(DMOD_SRCS:%=%.chk) \
	$(LINKMOD_SRCS:%=%.chk) \
	$(HEADERS:%=%.chk)

XXX_CHK = \
	$(KMOD_SRCS:%=%.xxxchk)

USR_HDRCHK =	$(HDRCHK_USRHDRS:%=%.uhdrchk)
SYS_HDRCHK =	$(HDRCHK_SYSHDRS:%=%.shdrchk)

KMOD_OBJS =	$(KMOD_SRCS:%.c=%.o)
DMOD_OBJS =	$(DMOD_SRCS:%.c=%.o)
LINKMOD_OBJS =	$(LINKMOD_SRCS:%.c=%.o)

kvm :	CPPFLAGS =	$(KERNEL_CPPFLAGS)
kvm :	CFLAGS =	$(KERNEL_CFLAGS)

kvm.so :	CPPFLAGS =	$(DMOD_CPPFLAGS)
kvm.so :	CFLAGS =	$(DMOD_CFLAGS)
kvm.so :	LDFLAGS =	$(DMOD_LDFLAGS)
kvm.so :	LIBS =		$(DMOD_LIBS)

JOY_kvm_link.so :	CPPFLAGS =	$(LINKMOD_CPPFLAGS)
JOY_kvm_link.so :	CFLAGS =	$(LINKMOD_CFLAGS)
JOY_kvm_link.so :	LDFLAGS =	$(LINKMOD_LDFLAGS)
JOY_kvm_link.so :	LIBS =		$(LINKMOD_LIBS)

world: kvm kvm.so JOY_kvm_link.so

kvm: $(KMOD_OBJS)
	$(LD) -r -o $@ $(KMOD_OBJS)
	$(CTFCONVERT) -L VERSION -o $@ $@

kvm.so: $(DMOD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(DMOD_OBJS) $(LIBS)
	$(CTFCONVERT) -L VERSION -o $@ $@

JOY_kvm_link.so: $(LINKMOD_OBJS)
	$(CC) -m32 $(LDFLAGS) -o $@ $(LINKMOD_OBJS) $(LIBS)
	$(CTFCONVERT) -L VERSION -o $@ $@

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

install: world
	@echo "==> Installing kvm module (to $(DESTDIR)/)"
	@mkdir -p $(DESTDIR)/usr/kernel/drv/amd64
	@cp kvm $(DESTDIR)/usr/kernel/drv/amd64/kvm
	@cp kvm.conf $(DESTDIR)/usr/kernel/drv
	@mkdir -p $(DESTDIR)/usr/lib/mdb/kvm/amd64
	@cp kvm.so $(DESTDIR)/usr/lib/mdb/kvm/amd64
	@mkdir -p $(DESTDIR)/usr/lib/devfsadm/linkmod
	@cp JOY_kvm_link.so $(DESTDIR)/usr/lib/devfsadm/linkmod

check: $(CSTYLE_CHK) $(XXX_CHK) $(USR_HDRCHK) $(SYS_HDRCHK)

%.chk: %
	$(CSTYLE) $<

%.xxxchk: %
	./tools/xxxcheck $<

%.uhdrchk: %
	$(HDRCHK) $(HDRCHK_USRFLAG) $<

%.shdrchk: %
	$(HDRCHK) $(HDRCHK_SYSFLAG) $<

update:
	git pull --rebase

clean:
	@pfexec rm -f *.o kvm kvm.so JOY_kvm_link.so

.PHONY: manifest
manifest:
	cp manifest $(DESTDIR)/$(DESTNAME)

.PHONY: mancheck_conf
mancheck_conf:

uninstall:
	@pfexec rem_drv kvm || /bin/true
	@pfexec rm -f /usr/kernel/drv/kvm* /usr/kernel/drv/amd64/kvm*
