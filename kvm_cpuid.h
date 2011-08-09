/*
 * GPL HEADER START
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * GPL HEADER END
 *
 * Copyright 2011 various Linux Kernel contributors.
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */
/*
 * Common CPUID definitions for KVM
 *
 * Derived from Linux arch/x86/include/asm/cpufeature.h
 */

#ifndef __KVM_CPUID_H
#define	__KVM_CPUID_H

/* Intel-defined CPU features, CPUID level 0x00000001 (edx), word 0 */
#define	X86_FEATURE_FPU		(0 * 32 + 0)    /* Onboard FPU */
#define	X86_FEATURE_VME		(0 * 32 + 1)    /* Virtual Mode Extensions */
#define	X86_FEATURE_DE		(0 * 32 + 2)    /* Debugging Extensions */
#define	X86_FEATURE_PSE		(0 * 32 + 3)    /* Page Size Extensions */
#define	X86_FEATURE_TSC		(0 * 32 + 4)    /* Time Stamp Counter */
#define	X86_FEATURE_MSR		(0 * 32 + 5)    /* Model-Specific Registers */
#define	X86_FEATURE_PAE		(0 * 32 + 6)    /* Phys. Address Extensions */
#define	X86_FEATURE_MCE		(0 * 32 + 7)    /* Machine Check Exception */
#define	X86_FEATURE_CX8		(0 * 32 + 8)    /* CMPXCHG8 instruction */
#define	X86_FEATURE_APIC	(0 * 32 + 9)    /* Onboard APIC */
#define	X86_FEATURE_SEP		(0 * 32 + 11)   /* SYSENTER/SYSEXIT */
#define	X86_FEATURE_MTRR	(0 * 32 + 12)   /* Memory Type Range Regs. */
#define	X86_FEATURE_PGE		(0 * 32 + 13)   /* Page Global Enable */
#define	X86_FEATURE_MCA		(0 * 32 + 14)   /* Machine Check Architecture */
#define	X86_FEATURE_CMOV	(0 * 32 + 15)   /* CMOV instructions */
						/*  (+ FCMOVcc, FCOMI w/ FPU) */
#define	X86_FEATURE_PAT		(0 * 32 + 16)   /* Page Attribute Table */
#define	X86_FEATURE_PSE36	(0 * 32 + 17)   /* 36-bit PSEs */
#define	X86_FEATURE_PN		(0 * 32 + 18)   /* Processor serial number */
#define	X86_FEATURE_CLFLSH	(0 * 32 + 19)   /* "clflush" instruction */
#define	X86_FEATURE_DS		(0 * 32 + 21)   /* "dts" Debug Store */
#define	X86_FEATURE_ACPI	(0 * 32 + 22)   /* ACPI via MSR */
#define	X86_FEATURE_MMX		(0 * 32 + 23)   /* Multimedia Extensions */
#define	X86_FEATURE_FXSR	(0 * 32 + 24)   /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define	X86_FEATURE_XMM		(0 * 32 + 25)   /* "sse" */
#define	X86_FEATURE_XMM2	(0 * 32 + 26)   /* "sse2" */
#define	X86_FEATURE_SELFSNOOP	(0 * 32 + 27)   /* "ss" CPU self snoop */
#define	X86_FEATURE_HT		(0 * 32 + 28)   /* Hyper-Threading */
#define	X86_FEATURE_ACC		(0 * 32 + 29)   /* "tm" Auto. clock control */
#define	X86_FEATURE_IA64	(0 * 32 + 30)   /* IA-64 processor */
#define	X86_FEATURE_PBE		(0 * 32 + 31)   /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define	X86_FEATURE_SYSCALL	(1 * 32 + 11)   /* SYSCALL/SYSRET */
#define	X86_FEATURE_MP		(1 * 32 + 19)   /* MP Capable. */
#define	X86_FEATURE_NX		(1 * 32 + 20)   /* Execute Disable */
#define	X86_FEATURE_MMXEXT	(1 * 32 + 22)   /* AMD MMX extensions */
#define	X86_FEATURE_FXSR_OPT	(1 * 32 + 25)   /* FXSAVE/FXRSTOR optimiztns */
#define	X86_FEATURE_GBPAGES	(1 * 32 + 26)   /* "pdpe1gb" GB pages */
#define	X86_FEATURE_RDTSCP	(1 * 32 + 27)   /* RDTSCP */
#define	X86_FEATURE_LM		(1 * 32 + 29)   /* Long Mode (x86-64) */
#define	X86_FEATURE_3DNOWEXT	(1 * 32 + 30)   /* AMD 3DNow! extensions */
#define	X86_FEATURE_3DNOW	(1 * 32 + 31)   /* 3DNow! */

/* cpu types for specific tunings: */
#define	X86_FEATURE_K8		(3 * 32 + 4)    /* "" Opteron, Athlon64 */
#define	X86_FEATURE_K7		(3 * 32 + 5)    /* "" Athlon */
#define	X86_FEATURE_P3		(3 * 32 + 6)    /* "" P3 */
#define	X86_FEATURE_P4		(3 * 32 + 7)    /* "" P4 */
#define	X86_FEATURE_CONSTANT_TSC	(3 * 32 + 8)	/* TSC ticks at */
							/* constant rate */
#define	X86_FEATURE_UP		(3 * 32 + 9)    /* smp kernel running on up */
#define	X86_FEATURE_FXSAVE_LEAK	(3 * 32 + 10)   /* FXSAVE leaks FOP/FIP/FOP */
#define	X86_FEATURE_ARCH_PERFMON	(3 * 32 + 11)  /* Intel Arch. PerfMon */
#define	X86_FEATURE_PEBS	(3 * 32 + 12)   /* Precise-Event Based Smplng */
#define	X86_FEATURE_BTS		(3 * 32 + 13)   /* Branch Trace Store */
#define	X86_FEATURE_SYSCALL32	(3 * 32 + 14)   /* syscall in ia32 userspace */
#define	X86_FEATURE_SYSENTER32	(3 * 32 + 15)   /* sysenter in ia32 userspace */
#define	X86_FEATURE_REP_GOOD	(3 * 32 + 16)   /* rep microcode works well */
#define	X86_FEATURE_MFENCE_RDTSC	(3 * 32 + 17)	/* Mfence */
							/* synchronizes RDTSC */
#define	X86_FEATURE_LFENCE_RDTSC	(3 * 32 + 18)	/* Lfence */
							/* synchronizes RDTSC */
#define	X86_FEATURE_11AP	(3 * 32 + 19)   /* Bad local APIC aka 11AP */
#define	X86_FEATURE_NOPL	(3 * 32 + 20)   /* NOPL (0F 1F) instructions */
#define	X86_FEATURE_AMDC1E	(3 * 32 + 21)   /* AMD C1E detected */
#define	X86_FEATURE_XTOPOLOGY	(3 * 32 + 22)   /* topology enum extensions */
#define	X86_FEATURE_TSC_RELIABLE	(3 * 32 + 23)  /* TSC is reliable */
#define	X86_FEATURE_NONSTOP_TSC	(3 * 32 + 24)   /* TSC continues in C states */
#define	X86_FEATURE_CLFLUSH_MONITOR	(3 * 32 + 25)	/* clflush reqd w/ */
							/* monitor */
#define	X86_FEATURE_EXTD_APICID	(3 * 32 + 26)   /* extended APICID (8 bits) */
#define	X86_FEATURE_AMD_DCM	(3 * 32 + 27)   /* multi-node processor */
#define	X86_FEATURE_APERFMPERF	(3 * 32 + 28)   /* APERFMPERF */

/* Intel-defined CPU features, CPUID level 0x00000001	(ecx), word 4 */
#define	X86_FEATURE_XMM3	(4 * 32 + 0)    /* "pni" SSE-3 */
#define	X86_FEATURE_PCLMULQDQ	(4 * 32 + 1)    /* PCLMULQDQ instruction */
#define	X86_FEATURE_DTES64	(4 * 32 + 2)    /* 64-bit Debug Store */
#define	X86_FEATURE_MWAIT	(4 * 32 + 3)    /* "monitor" Monitor/Mwait */
#define	X86_FEATURE_DSCPL	(4 * 32 + 4)    /* ds_cpl CPL Qual Debug Str */
#define	X86_FEATURE_VMX		(4 * 32 + 5)    /* Hardware virtualization */
#define	X86_FEATURE_SMX		(4 * 32 + 6)    /* Safer mode */
#define	X86_FEATURE_EST		(4 * 32 + 7)    /* Enhanced SpeedStep */
#define	X86_FEATURE_TM2		(4 * 32 + 8)    /* Thermal Monitor 2 */
#define	X86_FEATURE_SSSE3	(4 * 32 + 9)    /* Supplemental SSE-3 */
#define	X86_FEATURE_CID		(4 * 32 + 10)   /* Context ID */
#define	X86_FEATURE_FMA		(4 * 32 + 12)   /* Fused multiply-add */
#define	X86_FEATURE_CX16	(4 * 32 + 13)   /* CMPXCHG16B */
#define	X86_FEATURE_XTPR	(4 * 32 + 14)   /* Send Task Priority Msgs */
#define	X86_FEATURE_PDCM	(4 * 32 + 15)   /* Performance Capabilities */
#define	X86_FEATURE_DCA		(4 * 32 + 18)   /* Direct Cache Access */
#define	X86_FEATURE_XMM4_1	(4 * 32 + 19)   /* "sse4_1" SSE-4.1 */
#define	X86_FEATURE_XMM4_2	(4 * 32 + 20)   /* "sse4_2" SSE-4.2 */
#define	X86_FEATURE_X2APIC	(4 * 32 + 21)   /* x2APIC */
#define	X86_FEATURE_MOVBE	(4 * 32 + 22)   /* MOVBE instruction */
#define	X86_FEATURE_POPCNT	(4 * 32 + 23)   /* POPCNT instruction */
#define	X86_FEATURE_AES		(4 * 32 + 25)   /* AES instructions */
#define	X86_FEATURE_XSAVE	(4 * 32 + 26)   /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define	X86_FEATURE_OSXSAVE	(4 * 32 + 27)   /* "" XSAVE enabled in the OS */
#define	X86_FEATURE_AVX		(4 * 32 + 28)   /* Advanced Vector Extensions */
#define	X86_FEATURE_HYPERVISOR	(4 * 32 + 31)   /* Running on a hypervisor */
/* More extended AMD flags: CPUID level 0x80000001, ecx, word 6 */
#define	X86_FEATURE_LAHF_LM	(6 * 32 + 0)    /* LAHF/SAHF in long mode */
#define	X86_FEATURE_CMP_LEGACY	(6 * 32 + 1)    /* HyperThreading invalid */
#define	X86_FEATURE_SVM		(6 * 32 + 2)    /* Secure virtual machine */
#define	X86_FEATURE_EXTAPIC	(6 * 32 + 3)    /* Extended APIC space */
#define	X86_FEATURE_CR8_LEGACY	(6 * 32 + 4)    /* CR8 in 32-bit mode */
#define	X86_FEATURE_ABM		(6 * 32 + 5)    /* Advanced bit manipulation */
#define	X86_FEATURE_SSE4A	(6 * 32 + 6)    /* SSE-4A */
#define	X86_FEATURE_MISALIGNSSE	(6 * 32 + 7)    /* Misaligned SSE mode */
#define	X86_FEATURE_3DNOWPREFETCH	(6 * 32 + 8)  /* 3DNow prefetch */
#define	X86_FEATURE_OSVW	(6 * 32 + 9)    /* OS Visible Workaround */
#define	X86_FEATURE_IBS		(6 * 32 + 10)   /* Instruction Based Sampling */
#define	X86_FEATURE_SSE5	(6 * 32 + 11)   /* SSE-5 */
#define	X86_FEATURE_SKINIT	(6 * 32 + 12)   /* SKINIT/STGI instructions */
#define	X86_FEATURE_WDT		(6 * 32 + 13)   /* Watchdog timer */
#define	X86_FEATURE_NODEID_MSR	(6 * 32 + 19)   /* NodeId MSR */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
#define	X86_FEATURE_RECOVERY	(2 * 32 + 0)    /* CPU in recovery mode */
#define	X86_FEATURE_LONGRUN	(2 * 32 + 1)    /* Longrun power control */
#define	X86_FEATURE_LRTI	(2 * 32 + 3)    /* LongRun table interface */
						/* More extended AMD flags: */
						/* CPUID level 0x80000001, */
						/* ecx, word 6 */

#endif
