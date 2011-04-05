#!/usr/sbin/dtrace -Zs

#pragma D option quiet

/*
 * This checks for why we've exited based on using the library file for exit
 * errnos: exitno.d
 */

kvm-vexit
{
	printf("Exited: %s\n", strexitno[arg1]);
}
