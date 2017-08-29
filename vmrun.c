//
// =========================================================
// x86 Hardware Assisted virtualization demo for AMD-V (SVM)
// =========================================================
//
// Description: A very basic driver that walks
// through all the steps to do a successful vmrun.
// After vmrun, the guest code does a vmmcall and #vmexits
// back to the host. The guest state mirrors the host.
//
// References:
//
// 1. AMD64 Architecture Programmer's Manual
//    (Vol 2: System Programming)
// 2. svm.c from the Linux kernel
//    (KVM sources)
// 3. Original Intel VT-x vmlaunch demo
//    (https://github.com/vishmohan/vmlaunch)
//
// Author:
//
// Elias Kouskoumvekakis (https://eliaskousk.teamdac.com)
//
// ===============================================================
//
// > sudo insmod vmrun.ko
//
// dmesg:
//
// [  420.894248] Initializing AMD-V (SVM) vmrun driver
// [  420.894252] SVM is supported and enabled on CPU
// [  420.894255] Turned on MSR EFER.svme
// [  420.894266] Guest #vmexit reason: 0x12
// [  420.894268] Enabled Interrupts
//
// ...
//
// > sudo rmmod vmrun.ko
//
// dmesg:
//
// [  509.458658] Turned off MSR EFER.svme
//
// ===============================================================
//

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/virtext.h>
#include "vmrun.h"

MODULE_LICENSE("Dual BSD/GPL");

char *vmcb_guest_region;
long int vmcb_phy_region = 0;
u16 tr_sel; //selector for task register

static DEFINE_PER_CPU(struct svm_vcpu *, local_vcpu);
static DEFINE_PER_CPU(struct svm_cpu_data *, svm_data);
static DEFINE_PER_CPU(struct vmcb *, svm_area);

static void restore_registers(void);

static void initialize_16bit_host_guest_state(void)
{
	unsigned long field,field1;
	u16 	    value;
	field = VMX_HOST_ES_SEL;
	field1 = VMX_GUEST_ES_SEL;
	asm ("movw %%es, %%ax\n"
	:"=a"(value)
	);
	do_vmwrite16(field,value);
	do_vmwrite16(field1,value);

	field = VMX_HOST_CS_SEL;
	field1 = VMX_GUEST_CS_SEL;
	asm ("movw %%cs, %%ax\n"
	: "=a"(value));
	do_vmwrite16(field,value);
	do_vmwrite16(field1,value);

	field = VMX_HOST_SS_SEL;
	field1 = VMX_GUEST_SS_SEL;
	asm ("movw %%ss, %%ax\n"
	: "=a"(value));
	do_vmwrite16(field,value);
	do_vmwrite16(field1,value);

	field = VMX_HOST_DS_SEL;
	field1 = VMX_GUEST_DS_SEL;
	asm ("movw %%ds, %%ax\n"
	: "=a"(value));
	do_vmwrite16(field,value);
	do_vmwrite16(field1,value);

	field = VMX_HOST_FS_SEL;
	field1 = VMX_GUEST_FS_SEL;
	asm ("movw %%fs, %%ax\n"
	: "=a"(value));
	do_vmwrite16(field,value);
	do_vmwrite16(field1,value);

	field = VMX_HOST_GS_SEL;
	field1 = VMX_GUEST_GS_SEL;
	asm ("movw %%gs, %%ax\n"
	: "=a"(value));
	do_vmwrite16(field,value);
	do_vmwrite16(field1,value);

	field = VMX_HOST_TR_SEL;
	field1 = VMX_GUEST_TR_SEL;
	asm("str %%ax\n" : "=a"(tr_sel));
	do_vmwrite16(field,tr_sel);
	do_vmwrite16(field1,tr_sel);

	field = VMX_GUEST_LDTR_SEL;
	asm("sldt %%ax\n" : "=a"(value));
	do_vmwrite16(field,value);

}

static void initialize_64bit_control(void)
{
	unsigned long field;
	u64 	    value;

	field = VMX_IO_BITMAP_A_FULL;
	io_bitmap_a_phy_region = __pa(io_bitmap_a_region);
	value = io_bitmap_a_phy_region;
	do_vmwrite64(field,value);

	field = VMX_IO_BITMAP_B_FULL;
	io_bitmap_b_phy_region = __pa(io_bitmap_b_region);
	value = io_bitmap_b_phy_region;
	do_vmwrite64(field,value);

	field = VMX_MSR_BITMAP_FULL;
	msr_bitmap_phy_region = __pa(msr_bitmap_region);
	value = msr_bitmap_phy_region;
	do_vmwrite64(field,value);

	field = VMX_VIRTUAL_APIC_PAGE_ADDR_FULL;
	virtual_apic_page_phy_region = __pa(virtual_apic_page);
	value = virtual_apic_page_phy_region;
	do_vmwrite64(field,value);

	field = VMX_EXECUTIVE_VMCS_PTR_FULL;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_TSC_OFFSET_FULL;
	value = 0;
	do_vmwrite64(field,value);

}

static void initialize_64bit_host_guest_state(void)
{
	unsigned long field;
	u64 	    value;
	field = VMX_VMS_LINK_PTR_FULL;
	value = 0xffffffffffffffffull;
	do_vmwrite64(field,value);
	field = VMX_GUEST_IA32_DEBUGCTL_FULL;
	value = 0;
	do_vmwrite64(field,value);
}

static void initialize_32bit_control(void)
{
	unsigned long field;
	u32 	    value;

	field = VMX_PIN_VM_EXEC_CONTROLS;
	value = 0x1f ;
	do_vmwrite32(field,value);

	field = VMX_PROC_VM_EXEC_CONTROLS;
	value = 0x0401e172 ;
	do_vmwrite32(field,value);

	field = VMX_EXCEPTION_BITMAP;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	field = VMX_PF_EC_MASK;
	value = 0x0 ;
	do_vmwrite32(field,value);

	field = VMX_PF_EC_MATCH;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_CR3_TARGET_COUNT;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_EXIT_CONTROLS;
	value = 0x36fff ;
	do_vmwrite32(field,value);

	field = VMX_EXIT_MSR_STORE_COUNT;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_EXIT_MSR_LOAD_COUNT;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_ENTRY_CONTROLS;
	value = 0x13ff ;
	do_vmwrite32(field,value);

	field = VMX_ENTRY_MSR_LOAD_COUNT;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_ENTRY_INT_INFO_FIELD;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_ENTRY_EXCEPTION_EC;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_ENTRY_INSTR_LENGTH;
	value = 0 ;
	do_vmwrite32(field,value);

	field = VMX_TPR_THRESHOLD;
	value = 0 ;
	do_vmwrite32(field,value);
}

static void initialize_32bit_host_guest_state(void)
{
	unsigned long field;
	u32 	      value;
	u64           gdtb;
	u64	      trbase;
	u64           trbase_lo;
	u64           trbase_hi;
	u64 	      realtrbase;
	u64           idtb;
	u32           unusable_ar = 0x10000;
	u32           usable_ar;
	u16           sel_value;

	field = VMX_GUEST_ES_LIMIT;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	field = VMX_GUEST_ES_ATTR;
	value = unusable_ar;
	do_vmwrite32(field,value);

	field = VMX_GUEST_CS_LIMIT;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	asm ("movw %%cs, %%ax\n"
	: "=a"(sel_value));
	asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value));
	usable_ar = usable_ar>>8;
	usable_ar &= 0xf0ff; //clear bits 11:8

	field = VMX_GUEST_CS_ATTR;
	do_vmwrite32(field,usable_ar);
	value = do_vmread(field);

	field = VMX_GUEST_SS_LIMIT;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	asm ("movw %%ss, %%ax\n"
	: "=a"(sel_value));
	asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value));
	usable_ar = usable_ar>>8;
	usable_ar &= 0xf0ff; //clear bits 11:8

	field = VMX_GUEST_SS_ATTR;
	do_vmwrite32(field,usable_ar);

	field = VMX_GUEST_DS_LIMIT;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	field = VMX_GUEST_DS_ATTR;
	value = unusable_ar;
	do_vmwrite32(field,value);

	field = VMX_GUEST_FS_LIMIT;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	field = VMX_GUEST_FS_ATTR;
	value = unusable_ar;
	do_vmwrite32(field,value);

	field = VMX_GUEST_GS_LIMIT;
	value = 0xffffffff ;
	do_vmwrite32(field,value);

	field = VMX_GUEST_GS_ATTR;
	value = unusable_ar;
	do_vmwrite32(field,value);

	field = VMX_GUEST_LDTR_LIMIT;
	value = 0x0;
	do_vmwrite32(field,value);

	field = VMX_GUEST_LDTR_ATTR;
	value = unusable_ar;
	do_vmwrite32(field,value);

	field = VMX_GUEST_TR_LIMIT;
	asm volatile("mov %%rax, %%rax"
	:
	:"a"(tr_sel)
	);
	asm("lsl %%eax, %%eax\n" :"=a"(value));
	do_vmwrite32(field,value);

	//asm("str %%ax\n" : "=a"(sel_value));
	asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(tr_sel));
	usable_ar = usable_ar>>8;

	field = VMX_GUEST_TR_ATTR;
	do_vmwrite32(field,usable_ar);

	asm("sgdt %0\n" : :"m"(gdtb));
	value = gdtb&0x0ffff;
	gdtb = gdtb>>16; //base

	if((gdtb>>47&0x1)){
		gdtb |= 0xffff000000000000ull;
	}

	field = VMX_GUEST_GDTR_LIMIT;
	do_vmwrite32(field,value);

	field = VMX_GUEST_GDTR_BASE;
	do_vmwrite64(field,gdtb);
	field = VMX_HOST_GDTR_BASE;
	do_vmwrite64(field,gdtb);

	//trbase = gdtb + 0x40;
	trbase = gdtb + tr_sel;
	if((trbase>>47&0x1)){
		trbase |= 0xffff000000000000ull;
	}

	// SS segment override
	asm("mov %0,%%rax\n"
		".byte 0x36\n"
		"movq (%%rax),%%rax\n"
	:"=a"(trbase_lo) :"0"(trbase)
	);

	realtrbase = ((trbase_lo>>16) & (0x0ffff)) | (((trbase_lo>>32)&0x000000ff) << 16) | (((trbase_lo>>56)&0xff) << 24);

	// SS segment override for upper32 bits of base in ia32e mode
	asm("mov %0,%%rax\n"
		".byte 0x36\n"
		"movq 8(%%rax),%%rax\n"
	:"=a"(trbase_hi) :"0"(trbase)
	);

	realtrbase = realtrbase |   (trbase_hi<<32) ;

	field = VMX_HOST_TR_BASE;
	do_vmwrite64(field,realtrbase);

	field = VMX_GUEST_TR_BASE;
	do_vmwrite64(field,realtrbase);


	asm("sidt %0\n" : :"m"(idtb));
	value = idtb&0x0ffff;
	idtb = idtb>>16; //base

	if((idtb>>47&0x1)){
		idtb |= 0xffff000000000000ull;
	}

	field = VMX_GUEST_IDTR_LIMIT;
	do_vmwrite32(field,value);

	field = VMX_GUEST_IDTR_BASE;
	do_vmwrite64(field,idtb);
	field = VMX_HOST_IDTR_BASE;
	do_vmwrite64(field,idtb);

	field = VMX_GUEST_INTERRUPTIBILITY_INFO;
	value = 0;
	do_vmwrite32(field,value);

	field = VMX_GUEST_ACTIVITY_STATE;
	value = 0;
	do_vmwrite32(field,value);

	field = VMX_GUEST_SMBASE;
	value = 0;
	do_vmwrite32(field,value);

	asm volatile("mov $0x174, %rcx\n");
	asm("rdmsr\n");
	asm("mov %%rax, %0\n" : :"m"(value):"memory");
	field  = VMX_HOST_IA32_SYSENTER_CS;
	do_vmwrite32(field,value);
	field = VMX_GUEST_IA32_SYSENTER_CS;
	do_vmwrite32(field,value);
}

static void initialize_naturalwidth_control(void)
{
	unsigned long field;
	u64 	      value;

	field = VMX_CR0_MASK;
	value = 0;
	do_vmwrite64(field,value);
	field = VMX_CR4_MASK;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_CR0_READ_SHADOW;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_CR4_READ_SHADOW;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_CR3_TARGET_0;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_CR3_TARGET_1;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_CR3_TARGET_2;
	value = 0;
	do_vmwrite64(field,value);

	field = VMX_CR3_TARGET_3;
	value = 0;
	do_vmwrite64(field,value);
}

static void initialize_naturalwidth_host_guest_state(void)
{
	unsigned long field,field1;
	u64 	      value;
	int           fs_low;
	int           gs_low;

	field =  VMX_HOST_CR0;
	field1 = VMX_GUEST_CR0;
	asm ("movq %%cr0, %%rax\n"
	:"=a"(value)
	);
	do_vmwrite64(field,value);
	do_vmwrite64(field1,value);

	field =  VMX_HOST_CR3;
	field1 = VMX_GUEST_CR3;
	asm ("movq %%cr3, %%rax\n"
	:"=a"(value)
	);
	do_vmwrite64(field,value);
	do_vmwrite64(field1,value);

	field =  VMX_HOST_CR4;
	field1 = VMX_GUEST_CR4;
	asm ("movq %%cr4, %%rax\n"
	:"=a"(value)
	);
	do_vmwrite64(field,value);
	do_vmwrite64(field1,value);

	value=0;
	field1 = VMX_GUEST_ES_BASE;
	do_vmwrite64(field1,value);
	field1 = VMX_GUEST_CS_BASE;
	do_vmwrite64(field1,value);
	field1 = VMX_GUEST_SS_BASE;
	do_vmwrite64(field1,value);
	field1 = VMX_GUEST_DS_BASE;
	do_vmwrite64(field1,value);
	field1 = VMX_GUEST_LDTR_BASE;
	do_vmwrite64(field1,value);

	value = 0;
	field =  VMX_HOST_FS_BASE;
	field1 = VMX_GUEST_FS_BASE;
	asm volatile("mov $0xc0000100, %rcx\n");
	asm volatile("rdmsr\n" :"=a"(fs_low) : :"%rdx");
	//asm volatile ("mov %%rax, %0\n" : :"m"(fs_low) :"memory");
	asm volatile ("shl $32, %%rdx\n" :"=d"(value));
	value|=fs_low;
	do_vmwrite64(field1,value);
	do_vmwrite64(field,value);

	value = 0;
	field =  VMX_HOST_GS_BASE;
	field1 = VMX_GUEST_GS_BASE;
	asm volatile("mov $0xc0000101, %rcx\n");
	asm volatile("rdmsr\n" :"=a"(gs_low) : :"%rdx");
	//asm volatile ("mov %%rax, %0\n" : :"m"(gs_low) :"memory");
	asm volatile ("shl $32, %%rdx\n" :"=d"(value));
	value|=gs_low;
	do_vmwrite64(field1,value);
	do_vmwrite64(field,value);

	field1 = VMX_GUEST_DR7;
	value = 0x400;
	do_vmwrite64(field1,value);

	field = VMX_HOST_RSP;
	field1 = VMX_GUEST_RSP;
	asm ("movq %%rsp, %%rax\n"
	:"=a"(value)
	);
	do_vmwrite64(field1,value);
	do_vmwrite64(field,value);

	/*
	field1 = VMX_GUEST_RIP;
	value = (u64) guest_entry_code;
	do_vmwrite64(field1,value);

	field1 = VMX_HOST_RIP;
	value  = (u64) handle_vmexit;
	do_vmwrite64(field1,value); */

	field1 = VMX_GUEST_RFLAGS;
	asm volatile("pushfq\n");
	asm volatile("popq %0\n" :"=m"(value)::"memory");
	do_vmwrite64(field1,value);

	field1 = VMX_GUEST_PENDING_DEBUG_EXCEPT;
	value = 0x0;
	do_vmwrite64(field1,value);

	field1 = VMX_GUEST_IA32_SYSENTER_ESP;
	field  = VMX_HOST_IA32_SYSENTER_ESP;
	asm volatile("mov $0x176, %rcx\n");
	asm("rdmsr\n");
	asm("mov %%rax, %0\n" : :"m"(value):"memory");
	asm("or %0, %%rdx\n"  : :"m"(value):"memory");
	do_vmwrite64(field1,value);
	do_vmwrite64(field,value);

	field1 = VMX_GUEST_IA32_SYSENTER_EIP;
	field =  VMX_HOST_IA32_SYSENTER_EIP;
	asm volatile("mov $0x175, %rcx\n");
	asm("rdmsr\n");
	asm("mov %%rax, %0\n" : :"m"(value):"memory");
	asm("or %0, %%rdx\n"  : :"m"(value):"memory");
	do_vmwrite64(field1,value);
	do_vmwrite64(field,value);

}

static void initialize_guest_vmcb(void)
{
	initialize_16bit_host_guest_state();

	initialize_64bit_control();
	initialize_64bit_host_guest_state();

	initialize_32bit_control();
	initialize_32bit_host_guest_state();

	initialize_naturalwidth_control();
	initialize_naturalwidth_host_guest_state();
}

static void save_registers(void)
{
	asm volatile("pushq %rcx\n"
		"pushq %rdx\n"
		"pushq %rax\n"
		"pushq %rbx\n");

}

static void restore_registers(void)
{
	asm volatile("popq %rbx\n"
		"popq %rax\n"
		"popq %rdx\n"
		"popq %rcx\n");

}

static void vmcb_init(struct svm_vcpu *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct vmcb_save_area *save = &svm->vmcb->save;

	svm->vcpu.arch.hflags = 0;

	set_cr_intercept(svm, INTERCEPT_CR0_READ);
	set_cr_intercept(svm, INTERCEPT_CR3_READ);
	set_cr_intercept(svm, INTERCEPT_CR4_READ);
	set_cr_intercept(svm, INTERCEPT_CR0_WRITE);
	set_cr_intercept(svm, INTERCEPT_CR3_WRITE);
	set_cr_intercept(svm, INTERCEPT_CR4_WRITE);
	if (!kvm_vcpu_apicv_active(&svm->vcpu))
		set_cr_intercept(svm, INTERCEPT_CR8_WRITE);

	set_dr_intercepts(svm);

	set_exception_intercept(svm, PF_VECTOR);
	set_exception_intercept(svm, UD_VECTOR);
	set_exception_intercept(svm, MC_VECTOR);
	set_exception_intercept(svm, AC_VECTOR);
	set_exception_intercept(svm, DB_VECTOR);

	set_intercept(svm, INTERCEPT_INTR);
	set_intercept(svm, INTERCEPT_NMI);
	set_intercept(svm, INTERCEPT_SMI);
	set_intercept(svm, INTERCEPT_SELECTIVE_CR0);
	set_intercept(svm, INTERCEPT_RDPMC);
	set_intercept(svm, INTERCEPT_CPUID);
	set_intercept(svm, INTERCEPT_INVD);
	set_intercept(svm, INTERCEPT_HLT);
	set_intercept(svm, INTERCEPT_INVLPG);
	set_intercept(svm, INTERCEPT_INVLPGA);
	set_intercept(svm, INTERCEPT_IOIO_PROT);
	set_intercept(svm, INTERCEPT_MSR_PROT);
	set_intercept(svm, INTERCEPT_TASK_SWITCH);
	set_intercept(svm, INTERCEPT_SHUTDOWN);
	set_intercept(svm, INTERCEPT_VMRUN);
	set_intercept(svm, INTERCEPT_VMMCALL);
	set_intercept(svm, INTERCEPT_VMLOAD);
	set_intercept(svm, INTERCEPT_VMSAVE);
	set_intercept(svm, INTERCEPT_STGI);
	set_intercept(svm, INTERCEPT_CLGI);
	set_intercept(svm, INTERCEPT_SKINIT);
	set_intercept(svm, INTERCEPT_WBINVD);
	set_intercept(svm, INTERCEPT_XSETBV);

	if (!kvm_mwait_in_guest()) {
		set_intercept(svm, INTERCEPT_MONITOR);
		set_intercept(svm, INTERCEPT_MWAIT);
	}

	control->iopm_base_pa = iopm_base;
	control->msrpm_base_pa = __pa(svm->msrpm);
	control->int_ctl = V_INTR_MASKING_MASK;

	init_seg(&save->es);
	init_seg(&save->ss);
	init_seg(&save->ds);
	init_seg(&save->fs);
	init_seg(&save->gs);

	save->cs.selector = 0xf000;
	save->cs.base = 0xffff0000;
	/* Executable/Readable Code Segment */
	save->cs.attrib = SVM_SELECTOR_READ_MASK | SVM_SELECTOR_P_MASK |
			  SVM_SELECTOR_S_MASK | SVM_SELECTOR_CODE_MASK;
	save->cs.limit = 0xffff;

	save->gdtr.limit = 0xffff;
	save->idtr.limit = 0xffff;

	init_sys_seg(&save->ldtr, SEG_TYPE_LDT);
	init_sys_seg(&save->tr, SEG_TYPE_BUSY_TSS16);

	svm_set_efer(&svm->vcpu, 0);
	save->dr6 = 0xffff0ff0;
	kvm_set_rflags(&svm->vcpu, 2);
	save->rip = 0x0000fff0;
	svm->vcpu.arch.regs[VCPU_REGS_RIP] = save->rip;

	/*
	 * svm_set_cr0() sets PG and WP and clears NW and CD on save->cr0.
	 * It also updates the guest-visible cr0 value.
	 */
	svm_set_cr0(&svm->vcpu, X86_CR0_NW | X86_CR0_CD | X86_CR0_ET);
	kvm_mmu_reset_context(&svm->vcpu);

	save->cr4 = X86_CR4_PAE;
	/* rdx = ?? */

	if (npt_enabled) {
		/* Setup VMCB for Nested Paging */
		control->nested_ctl = 1;
		clr_intercept(svm, INTERCEPT_INVLPG);
		clr_exception_intercept(svm, PF_VECTOR);
		clr_cr_intercept(svm, INTERCEPT_CR3_READ);
		clr_cr_intercept(svm, INTERCEPT_CR3_WRITE);
		save->g_pat = svm->vcpu.arch.pat;
		save->cr3 = 0;
		save->cr4 = 0;
	}
	svm->asid_generation = 0;

	svm->nested.vmcb = 0;
	svm->vcpu.arch.hflags = 0;

	if (boot_cpu_has(X86_FEATURE_PAUSEFILTER)) {
		control->pause_filter_count = 3000;
		set_intercept(svm, INTERCEPT_PAUSE);
	}

	if (avic)
		avic_init_vmcb(svm);

	mark_all_dirty(svm->vmcb);

	enable_gif(svm);

}

static struct svm_vcpu *vcpu_create(unsigned int id)
{
	struct svm_vcpu *vcpu;
	struct page *vmcb_page;
	int err;

	vcpu = kzalloc(sizeof(struct svm_vcpu), GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	vcpu->cpu = -1;
	vcpu->vcpu_id = id;

	err = -ENOMEM;
	vmcb_page = alloc_page(GFP_KERNEL);
	if (!vmcb_page)
		goto free_svm;

	vcpu->vmcb = page_address(vmcb_page);
	clear_page(vcpu->vmcb);
	vcpu->vmcb_pa = page_to_pfn(vmcb_page) << PAGE_SHIFT;
	vcpu->asid_generation = 0;
	vmcb_init(vcpu);

	return vcpu;

free_svm:
	kfree(vcpu);
out:
	return ERR_PTR(err);
}

static void vcpu_free(struct svm_vcpu *vcpu)
{
	__free_page(pfn_to_page(vcpu->vmcb_pa >> PAGE_SHIFT));
	kfree(vcpu);
}

static int cpu_init(int cpu)
{
	struct svm_cpu_data *sd;
	int r;

	sd = kzalloc(sizeof(struct svm_cpu_data), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;
	sd->cpu = cpu;
	sd->save_area = alloc_page(GFP_KERNEL);
	r = -ENOMEM;
	if (!sd->save_area)
		goto err;

	per_cpu(svm_data, cpu) = sd;

	return 0;

err:
	kfree(sd);
	return r;
}

static void cpu_uninit(int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, raw_smp_processor_id());

	if (!sd)
		return;

	per_cpu(svm_data, raw_smp_processor_id()) = NULL;
	__free_page(sd->save_area);
	kfree(sd);
}

static int turn_on_svm(void)
{
	int msr_efer_addr  = MSR_EFER_SVM_EN_ADDR;
	int msr_efer_value = 0;
	struct svm_cpu_data *sd;
	int me = raw_smp_processor_id();
	int cpu;
	int r;

	asm volatile("rdmsr\n" : "=a" (msr_efer_value)
			       : "c"  (msr_efer_addr)
			       : "%rdx");

	msr_efer_value |= (1 << MSR_EFER_SVM_EN_BIT);

	asm volatile("wrmsr\n" :
			       : "c" (msr_efer_addr), "a" (msr_efer_value)
			       : "memory");

	printk("Turned on MSR EFER.svme\n");

	for_each_possible_cpu(cpu) {
		r = cpu_init(cpu);
		if (r)
			return r;
	}

	sd = per_cpu(svm_data, me);
	if (!sd) {
		pr_err("%s: svm_data is NULL on %d\n", __func__, me);
		return -EINVAL;
	}

	sd->asid_generation = 1;

	asm volatile("cpuid\n\t" : "=b" ((sd->max_asid - 1))
				 : "a" (CPUID_EXT_A_SVM_LOCK_LEAF)
				 : "%rcx","%rdx");

	sd->next_asid = sd->max_asid + 1;

	asm volatile("wrmsr\n" :
			       : "c" (MSR_VM_HSAVE_PA), "a" (page_to_pfn(sd->save_area) << PAGE_SHIFT)
			       : "memory");

	return 0;
}

static void turn_off_svm(void)
{
	int msr_efer_addr  = MSR_EFER_SVM_EN_ADDR;
	int msr_efer_value = 0;
	int cpu;

	asm volatile("wrmsr\n" :
			       : "c" (MSR_VM_HSAVE_PA), "a" (0)
			       : "memory");

	for_each_possible_cpu(cpu)
		cpu_uninit(cpu);

	asm volatile("rdmsr\n" : "=a" (msr_efer_value)
			       : "c"  (msr_efer_addr)
			       : "%rdx");

	msr_efer_value &= ~(1 << MSR_EFER_SVM_EN_BIT);

	asm volatile("wrmsr\n" :
			       : "c" (msr_efer_addr), "a" (msr_efer_value)
			       : "memory");

	printk("Turned off MSR EFER.svme\n");
}

static int has_svm (void)
{
	int cpuid_leaf      = 0;
	int cpuid_value     = 0;
	int msr_vm_cr_addr  = 0;
	int msr_vm_cr_value = 0;

	//
	// See AMD64 APM
	// Vol.2, Chapter 15, Section 4 (Enabling SVM)
	//

	//
	// CPUID check (if SVM is supported)
	//

	cpuid_leaf  = CPUID_EXT_1_SVM_LEAF;

	asm volatile("cpuid\n\t" : "=c" (cpuid_value)
				 : "a"  (cpuid_leaf)
				 : "%rbx","%rdx");

	if (!((cpuid_value >> CPUID_EXT_1_SVM_BIT) & 1)) {
		printk("CPUID: SVM not supported");
		return 0;
	}

	//
	// MSR VM CR check (if SVM is disabled)
	//

	msr_vm_cr_addr  = MSR_VM_CR_SVM_DIS_ADDR;

	asm volatile("rdmsr\n" : "=a" (msr_vm_cr_value)
			       : "c"  (msr_vm_cr_addr)
			       : "%rdx");

	if (!(msr_vm_cr_value & (1 << MSR_VM_CR_SVM_DIS_BIT)))
		return 1;

	//
	// CPUID check (if SVM is locked)
	//

	cpuid_leaf  = CPUID_EXT_A_SVM_LOCK_LEAF;

	asm volatile("cpuid\n\t" : "=d" (cpuid_value)
			         : "a"  (cpuid_leaf)
			         : "%rbx","%rcx");

	if (!((cpuid_value >> CPUID_EXT_A_SVM_LOCK_BIT) & 1))
		printk("CPUID: SVM disabled at BIOS (not unlockable)");
	else
		printk("CPUID: SVM disabled at BIOS (with key)");

	return 0;
}

static int vmrun_init(void)
{
	int r;
	u64 value = 0;

	printk("Initializing AMD-V (SVM) vmrun driver\n");

	save_registers();

	if (has_svm()) {
		printk("SVM is supported and enabled on CPU\n");
	} else {
		printk("SVM not supported or enabled on CPU, nothing to be done\n");
		goto finish_here;
	}

	r = turn_on_svm();
	if (r)
		goto err;

	for (unsigned int i = 0; i < NR_VCPUS; i++) {
		vcpu_create(i);
	}

	//host rip
	asm ("movq $0x6c16, %rdx");
	asm ("movq $vmexit_handler, %rax");
	asm ("vmwrite %rax, %rdx");

	//guest rip
	asm ("movq $0x681e, %rdx");
	asm ("movq $guest_entry_point, %rax");
	asm ("vmwrite %rax, %rdx");

	printk("Doing vmrun now..\n");

	asm volatile (INSTR_SVM_CLGI);
	asm volatile (INSTR_SVM_VMRUN);
	asm volatile("jbe vmexit_handler\n");
	asm volatile("nop\n"); //will never get here
	asm volatile("guest_entry_point:");
	asm volatile(INSTR_SVM_VMMCALL);
	asm volatile("ud2\n"); //will never get here
	asm volatile("vmexit_handler:\n");

	printk("After #vmexit\n");

	// field_1 = VMX_EXIT_REASON;
	// value = do_vmread(field_1);
	// printk("Guest #vmexit reason: 0x%x\n", value);

	for (unsigned int i = 0; i < NR_VCPUS; i++) {
		vcpu_free(i);
	}

	turn_off_svm();

	asm volatile("sti\n");
	printk("Enabled Interrupts\n");

finish_here:
	printk("Done\n");

	restore_registers();

	return 0;

err:
	printk("Error\n");
	restore_registers();
	return r;
}


static void vmrun_exit(void) {



}

module_init(vmrun_init);
module_exit(vmrun_exit);
