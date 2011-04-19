#!/usr/sbin/dtrace -C

/*
 * Prints out the last several vmexits after a triple fault.  Must be run
 * with exitno.d.
 */

#pragma D option quiet
#pragma D option bufpolicy=ring
#pragma D option bufsize=16k

BEGIN
{
	start = timestamp;
}

kvm-vexit
{
	printf("t+%-14d cpu: %-3d  %-40s vpid: %-5d\n",
	    timestamp - start, cpu, strexitno[arg1],
	    vmregs[VMX_VIRTUAL_PROCESSOR_ID]);
	printf("   rip: %16x   rsp: %16x   rfl: %16x\n",
	    vmregs[VMX_GUEST_RIP], vmregs[VMX_GUEST_RSP],
	    vmregs[VMX_GUEST_RFLAGS]);
	printf("   cr0: %16x   cr3: %16x   cr4: %16x\n",
	    vmregs[VMX_GUEST_CR0], vmregs[VMX_GUEST_CR3],
	    vmregs[VMX_GUEST_CR4]);
	printf("   ldt: %16x   gdt: %16x   idt: %16x\n",
	    vmregs[VMX_GUEST_LDTR_BASE], vmregs[VMX_GUEST_GDTR_BASE],
	    vmregs[VMX_GUEST_IDTR_BASE]);
	printf("    cs:           base=%x limit=%x selector=%x access=%x\n",
	    vmregs[VMX_GUEST_CS_BASE],
	    vmregs[VMX_GUEST_CS_LIMIT],
	    vmregs[VMX_GUEST_CS_SELECTOR],
	    vmregs[VMX_GUEST_CS_AR_BYTES]);
	printf("    ds:           base=%x limit=%x selector=%x access=%x\n",
	    vmregs[VMX_GUEST_DS_BASE],
	    vmregs[VMX_GUEST_DS_LIMIT],
	    vmregs[VMX_GUEST_DS_SELECTOR],
	    vmregs[VMX_GUEST_DS_AR_BYTES]);
	printf("    es:           base=%x limit=%x selector=%x access=%x\n",
	    vmregs[VMX_GUEST_ES_BASE],
	    vmregs[VMX_GUEST_ES_LIMIT],
	    vmregs[VMX_GUEST_ES_SELECTOR],
	    vmregs[VMX_GUEST_ES_AR_BYTES]);
	printf("    fs:           base=%x limit=%x selector=%x access=%x\n",
	    vmregs[VMX_GUEST_FS_BASE],
	    vmregs[VMX_GUEST_FS_LIMIT],
	    vmregs[VMX_GUEST_FS_SELECTOR],
	    vmregs[VMX_GUEST_FS_AR_BYTES]);
	printf("    ss:           base=%x limit=%x selector=%x access=%x\n",
	    vmregs[VMX_GUEST_SS_BASE],
	    vmregs[VMX_GUEST_SS_LIMIT],
	    vmregs[VMX_GUEST_SS_SELECTOR],
	    vmregs[VMX_GUEST_SS_AR_BYTES]);
	printf("\n");
}

kvm-vexit
/arg1 == EXIT_REASON_TRIPLE_FAULT/
{
	exit(0);
}

