illumos-kvm: KVM for illumos
============================

KVM is the kernel virtual machine, a framework for the in-kernel acceleration
of QEMU.  illumos-kvm is a port of KVM to illumos, taking advantage of
illumos-specific constructs like DTrace, cyclics, mdb, kstat, OS
virtualization, network virtualization, ZFS, etc.  It is derived from the KVM
source for Linux 2.6.34, the longterm source for which may be found here:

    git://git.kernel.org/pub/scm/linux/kernel/git/longterm/linux-2.6.34.y.git

To date, this implementation has been verified with a wide range of guest
operating systems including illumos itself (both SmartOS and OpenIndiana
distributions), FreeBSD, Plan 9, QNX, ChromeOS, HaikuOS, Microsoft Windows
and Linux.

The design center for this work is to use the virtualization features made
available in the microprocessor -- and in particular, Intel's VMX.  As such,
behavior on microprocessors that do not support VMX -- and more specifically,
the extended page tables (EPT) found in second generation VMX support --
should be graceful failure, not degraded operation.

Divergences from KVM
--------------------

Divergences from KVM fall into several broad categories:  some functionality
has been removed or not implemented because it is obviated by features of
illumos (e.g., the custom tracing facility built into KVM); some functionality
has been removed because it is only relevant to hardware that lacks
virtualization support (e.g., older x86 hardware) or on hardware for which
illumos lacks support (e.g., PPC, s390); and some functionality has been
removed because the implementation complexity was simply too great relative
to its value.

Of this latter category, three areas of divergence merit special note.  First,
there is no support for pageable guest memory (that is, guest memory is locked
down).  While this is an opinionated decision at some level (in our
experience, memory oversell leads to unacceptable pathologies in all but the
idlest of workloads), we would welcome the work to integrate the KVM MMU
notifier support into illumos-kvm.

Second (and relatedly), illumos itself has no support for kernel same-page
mapping (KSM) as found in Linux.  While illumos could in principle add such
support, it is our experience that the memory that accrues from this is not
sufficiently significant to pay for the increase in implementation and
operator complexity.

Finally, there is no support currently for AMD SVM.  This is not a value
judgement of AMD's technology, but rather a reflection of limited engineering
and testing resources.  (In the spirit of full disclosure, it should be said
that the sponsor of illumos-kvm, Joyent, is an Intel-funded company -- but the
lack of AMD support reflects only engineering prioritization and lack of
testing infrastructure; AMD SVM support would be most welcome should someone
in the community be so motivated as to port and test it.)

Building illumos-kvm
--------------------

### Preparation

Edit the Makefile and appropriately set the path for the `KERNEL_SOURCE`
directory to point to the root of a checked out and built illumos directory.
Building illumos KVM requires several recent additions to illumos,
so be sure your illumos is up to date.

Verify that you have gcc 4.4.4 installed that is used to build illumos.
If you are not building this with SmartOS, you may need to modify the
Makefile such that CC is pointing to the correct gcc.

Verify that you either have SUNWmake or GNU make installed.

### Building

To build, simply use the default make target:

    $ make

To check style, header files, and other various nits:

    $ make check

Installing illumos-kvm
----------------------

### System requirements

To run illumos-kvm, you will need an illumos that has the fix for issue
1347 (integrated on 2011-08-11). Further, your machine will need to
support VMX.  To see if your machine supports VMX, run `isainfo -v` and
look for `vmx`, e.g.:

      % isainfo -v
      64-bit amd64 applications
            vmx sse4.2 sse4.1 ssse3 popcnt tscp cx16 sse3 sse2 sse fxsr mmx 
            cmov amd_sysc cx8 tsc fpu 
      32-bit i386 applications
            vmx sse4.2 sse4.1 ssse3 popcnt tscp ahf cx16 sse3 sse2 sse fxsr mmx 
            cmov sep cx8 tsc fpu 

If you do not see `vmx` in this output, the `kvm` driver will be unable to
attach.

### Required binaries

There are two mandatory artifacts to install, and two optional component:

* `kvm` is the driver itself
* `kvm.conf` is the driver configuration file
* `kvm.so` is the mdb module
* `JOY_kvm_link.so` is the devfsadm plugin

On the target machine, place `kvm` in `/kernel/drv/amd64` and `kvm.conf`
in `/kernel/drv`. Place `JOY_kvm_link.so` in `/usr/lib/devfsadm/linkmod` then:

    # add_drv kvm

You can verify that the driver installed and attached properly by checking for
its presence in /dev.

    # ls -l /dev/kvm

Running illumos-kvm
-------------------

To run KVM, you will need the build product of the illumos-kvm-cmd repo:
`qemu-system-x86_64`; please follow the instructions in the illumos-kvm-cmd
repo to execute QEMU such that KVM is enabled.

Monitoring illumos-kvm
----------------------

Once one or more VMs are running, there is a variety of tooling to help
understand the operating characteristics of the system.

### kvmstat

The `kvmstat` command, found in the illumos repository, can be used to monitor
VMs. For example, here is one second of `kvmstat` output from a machine
running two VMs (one 2 VCPU instance running Linux; another 4 VCPU instance
running the illumos-derived SmartOS):

       pid vcpu |  exits :  haltx   irqx  irqwx    iox  mmiox |   irqs   emul   eptv
      4668    0 |     23 :      6      0      0      1      0 |      6     16      0
      4668    1 |     25 :      6      1      0      1      0 |      6     16      0
      5026    0 |  17833 :    223   2946    707    106      0 |   3379  13315      0
      5026    1 |  18687 :    244   2761    512      0      0 |   3085  14803      0
      5026    2 |  15696 :    194   3452    542      0      0 |   3568  11230      0
      5026    3 |  16822 :    244   2817    487      0      0 |   3100  12963      0

As for the meaning of the columns, they are explained with `kvmstat -h`:

      # kvmstat -h
      Usage: kvmstat [interval [count]]

        Displays statistics for running kernel virtual machines, with one line
        per virtual CPU.  All statistics are reported as per-second rates.

        The columns are as follows:

          pid    =>  identifier of process controlling the virtual CPU
          vcpu   =>  virtual CPU identifier relative to its virtual machine
          exits  =>  virtual machine exits for the virtual CPU
          haltx  =>  virtual machine exits due to the HLT instruction
          irqx   =>  virtual machine exits due to a pending external interrupt
          irqwx  =>  virtual machine exits due to an open interrupt window
          iox    =>  virtual machine exits due to an I/O instruction
          mmiox  =>  virtual machine exits due to memory mapped I/O 
          irqs   =>  interrupts injected into the virtual CPU
          emul   =>  instructions emulated in the kernel
          eptv   =>  extended page table violations

### kstat

As one might expect, `kvmstat` is implemented in terms of kstat.  You
can use `kstat(1)` to browse the kstats from the `kvm` module:

       # kstat -m kvm
       ...
       module: kvm                      instance: 0     
       name:   vcpu-4                   class:    misc
        crtime                          4407.142410068
        exits                           5367443
        fpu-reload                      57302
        halt-exits                      317275
        halt-wakeup                     8991
        host-state-reload               503920
        hypercalls                      0
        insn-emulation                  3043881
        inst-emulation-fail             0
        invlpg                          0
        io-exits                        237191
        irq-exits                       1668
        irq-injections                  320339
        irq-window-exits                1635
        mmio-exits                      617
        nmi-injections                  0
        nmi-window-exits                0
        pf-fixed                        163629
        pf-guest                        0
        pid                             3949
        request-irq-exits               0
        signal-exits                    460
        snaptime                        43219.723435123
        zonename                        global
       
       module: kvm                      instance: 4     
       name:   vm                       class:    misc
        crtime                          4407.1241134
        lpages                          0
        mmu-cache-miss                  950
        mmu-flooded                     0
        mmu-pte-updated                 0
        mmu-pte-write                   56360
        mmu-pte-zapped                  0
        mmu-recycled                    0
        mmu-unsync-page                 0
        pid                             3949
        remote-tlb-flush                1511
        snaptime                        43219.723875091
        zonename                        global
       

### DTrace

While there is not currently a stable KVM provider, there are many SDT probes
in KVM; `dtrace -l -m sdt:kvm` to list these.

Of these, of particular note are the `kvm-guest-entry` and `kvm-guest-exit`
probes, which fire upon entry to and exit from a guest virtual machine.  To
determine context, one can use the `vmregs` variable present in illumos.

For example, here's a simple script that shows histograms of time spent in VM
guests on a per-PID and per-VCPU basis:

        #pragma D option quiet
        
        kvm-guest-entry
        {
                self->entry = timestamp;
        }
        
        kvm-guest-exit
        /self->entry/
        {
                @[pid, vmregs[VMX_VIRTUAL_PROCESSOR_ID]] =
                    quantize(timestamp - self->entry);
        }
        
        END
        {
                printa("pid %d, vcpu %d: %@d\n", @);
        }

Here's what the output of running the above might look like:

      pid 3949, vcpu 1: 
           value  ------------- Distribution ------------- count    
             512 |                                         0        
            1024 |@@@@@@@@@@@@@                            26805    
            2048 |@@@@@                                    11641    
            4096 |@@@@@@@                                  14187    
            8192 |@                                        1559     
           16384 |@                                        2931     
           32768 |@@@                                      5653     
           65536 |@@@@                                     8385     
          131072 |@@@                                      6926     
          262144 |@@@                                      6639     
          524288 |                                         785      
         1048576 |                                         0        

There are many other ways in which DTrace can be used to understand either
host or guest behavior; see the `tools` subdirectory from some sample D
scripts.

### mdb

The `kvm.so` build product is an mdb module that contains several useful
commands, including a `kvm` walker to iterate over all `struct kvm`
structures.

Contributing to illumos-kvm
---------------------------

Unless and until its volume dictate that it be elsewhere, illumos KVM
discussion should be on the `illumos-developer` mailing list.
Contributions are happily accepted; please send patches to 
`illumos-developer`.

