#!/usr/sbin/dtrace -Zs

#pragma D option quiet

kvm-xxx
{
	@[stringof(arg0), probefunc, arg1] = count();
}

tick-10sec
{
	printf("%-12s %-40s %-8s %8s\n", "FILE", "FUNCTION", "LINE", "COUNT");
	printa("%20s %8d %@8d\n", @);
}
