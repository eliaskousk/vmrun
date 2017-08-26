# vmrun

## Simple Linux kernel module for vmrun
The idea behind the driver is to demonstrate a real example of how to initialize 
the Virtual Machine Control Block (VMCB) and to use AMD-V (SVM) instructions to launch 
a virtual machine. The driver launches a guest (virtual machine) with vmrun, executes 
one instruction(that causes a #vmexit) and then returns to the host. For the vmrun 
instruction to execute successfully, a lot of cpu state (host and guest state) needs
to be initialized all of which is done by this driver. The driver also takes a simple 
approach in setting up the guest state by making it mirror the host state. This makes 
the design much simpler - for instance the guest does not need its own CR3, it shares 
it with the host. Inline assembly is used generously throughout the driver.

## One possible concern:
The VMCB does not have a host state field for LDTs. After a #vmexit, the processor 
loads the LDT selector to null. If a non-zero ldt selector is required before the 
module exits then the code after #vmexit may require a lldt <sel_value> to establish
the ldtr to a good state.

## Author
Elias Kouskoumvekakis
- [Contact]((first_name).(first_five_letters_of_surname)@stromasys.com)
- [Blog](http://eliaskousk.teamdac.com)


The idea from this demo came from the [vmlaunch](https://github.com/vishmohan/vmlaunch)
repository from Vish Mohan ([Blog](http://virtualizationtechnologyvt.blogspot.gr/)). That demo initializes and runs a virtual machine using the
Intel VT-x hardware virtualization extensions.

