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
static DEFINE_PER_CPU(struct svm_cpu_data *, local_cpu_data);
static DEFINE_PER_CPU(struct vmcb *, local_vmcb);

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

static void init_seg(struct vmcb_seg *seg)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK |
		      SVM_SELECTOR_WRITE_MASK; /* Read/Write Data Segment */
	seg->limit = 0xffff;
	seg->base = 0;
}

static void init_sys_seg(struct vmcb_seg *seg, uint32_t type)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | type;
	seg->limit = 0xffff;
	seg->base = 0;
}

static void vmcb_init(struct svm_vcpu *vcpu)
{
	struct vmcb_control_area *control = &vcpu->vmcb->control;
	struct vmcb_save_area *save = &vcpu->vmcb->save;

	control->intercept |= (1ULL << INTERCEPT_VMMCALL);
	control->clean &= ~(1 << VMCB_INTERCEPTS);

	// Not sure
	//
	//control->iopm_base_pa = iopm_base;
	//control->msrpm_base_pa = __pa(vcpu->msrpm);
	//control->int_ctl = V_INTR_MASKING_MASK;

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

	save->efer = vcpu->efer | EFER_SVME | EFER_LMA | EFER_LME;
	control->clean &= ~(1 << VMCB_CR);

	save->dr6 = 0xffff0ff0;
	save->rflags = 2;
	save->rip = 0x0000fff0;

	const unsigned long cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET | X86_CR0_PG | X86_CR0_WP;
	save->cr0 = cr0;
	control->clean &= ~(1 << VMCB_CR);
	save->cr4 = X86_CR4_PAE;
	control->clean = 0;

	vcpu->cr0 = cr0;
	vcpu->efer = EFER_LME | EFER_LMA;
	vcpu->regs[VCPU_REGS_RIP] = save->rip;
	vcpu->hflags = 0;
	vcpu->asid_generation = 0;
	vcpu->hflags |= HF_GIF_MASK;
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

static void vcpu_run(struct svm_vcpu *vcpu)
{
	// Guest rip
	asm volatile("movq $guest_entry_point, %rax");
	asm volatile("movq %%rax, %0" : "=r" (vcpu->vmcb->save.rip)
			              :
				      : "memory");
	asm ("movq %%rax, %0" : "=r" (vcpu->regs[VCPU_REGS_RIP])
			      :
			      : "memory");

	printk("Doing vmrun now...\n");

	asm volatile(
		INSTR_SVM_CLGI "\n\t"
		"push %%" _ASM_BP "; \n\t"
		"mov %c[rbx](%[vcpu]), %%" _ASM_BX " \n\t"
		"mov %c[rcx](%[vcpu]), %%" _ASM_CX " \n\t"
		"mov %c[rdx](%[vcpu]), %%" _ASM_DX " \n\t"
		"mov %c[rsi](%[vcpu]), %%" _ASM_SI " \n\t"
		"mov %c[rdi](%[vcpu]), %%" _ASM_DI " \n\t"
		"mov %c[rbp](%[vcpu]), %%" _ASM_BP " \n\t"
		"mov %c[r8](%[vcpu]),  %%r8  \n\t"
		"mov %c[r9](%[vcpu]),  %%r9  \n\t"
		"mov %c[r10](%[vcpu]), %%r10 \n\t"
		"mov %c[r11](%[vcpu]), %%r11 \n\t"
		"mov %c[r12](%[vcpu]), %%r12 \n\t"
		"mov %c[r13](%[vcpu]), %%r13 \n\t"
		"mov %c[r14](%[vcpu]), %%r14 \n\t"
		"mov %c[r15](%[vcpu]), %%r15 \n\t"

		/* Enter guest mode */
		"push %%" _ASM_AX " \n\t"
		"mov %c[vmcb](%[vcpu]), %%" _ASM_AX " \n\t"
		INSTR_SVM_VMLOAD "\n\t"
		INSTR_SVM_VMRUN "\n\t"
		INSTR_SVM_VMSAVE "\n\t"
		"pop %%" _ASM_AX " \n\t"

		/* Save guest registers, load host registers */
		"mov %%" _ASM_BX ", %c[rbx](%[vcpu]) \n\t"
		"mov %%" _ASM_CX ", %c[rcx](%[vcpu]) \n\t"
		"mov %%" _ASM_DX ", %c[rdx](%[vcpu]) \n\t"
		"mov %%" _ASM_SI ", %c[rsi](%[vcpu]) \n\t"
		"mov %%" _ASM_DI ", %c[rdi](%[vcpu]) \n\t"
		"mov %%" _ASM_BP ", %c[rbp](%[vcpu]) \n\t"
		"mov %%r8,  %c[r8](%[vcpu]) \n\t"
		"mov %%r9,  %c[r9](%[vcpu]) \n\t"
		"mov %%r10, %c[r10](%[vcpu]) \n\t"
		"mov %%r11, %c[r11](%[vcpu]) \n\t"
		"mov %%r12, %c[r12](%[vcpu]) \n\t"
		"mov %%r13, %c[r13](%[vcpu]) \n\t"
		"mov %%r14, %c[r14](%[vcpu]) \n\t"
		"mov %%r15, %c[r15](%[vcpu]) \n\t"
		"pop %%" _ASM_BP

		: // No outputs

		: [vcpu]"a"(vcpu),
		  [vmcb]"i"(offsetof(struct svm_vcpu, vmcb_pa)),
		  [rbx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RBX])),
		  [rcx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RCX])),
		  [rdx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RDX])),
		  [rsi]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RSI])),
		  [rdi]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RDI])),
		  [rbp]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RBP])),
		  [r8]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R8])),
		  [r9]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R9])),
		  [r10]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R10])),
		  [r11]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R11])),
		  [r12]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R12])),
		  [r13]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R13])),
		  [r14]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R14])),
		  [r15]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R15]))

		: "cc", "memory", "rbx", "rcx", "rdx", "rsi", "rdi",
		  "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15");

	printk("After #vmexit\n");
	asm volatile("jmp vmexit_handler\n");
	asm volatile("nop\n"); //will never get here

	asm volatile("guest_entry_point:");
	asm volatile(INSTR_SVM_VMMCALL);
	asm volatile("ud2\n"); //will never get here

	asm volatile("vmexit_handler:\n");
	printk("Guest #vmexit Info\n");
	printk("Code: 0x%x\n", vcpu->vmcb->control.exit_code);
	printk("Info 1: 0x%x\n", vcpu->vmcb->control.exit_info_1);
	printk("Info 2: 0x%x\n", vcpu->vmcb->control.exit_info_2);

	if (vcpu->vmcb->control.exit_code == SVM_EXIT_ERR) {
		pr_err("VMRUN Failed\n");
		return;
	}

	if (vcpu->vmcb->control.exit_code == SVM_EXIT_VMMCALL) {
		printk("VMRUN and VMMCALL Succeeded\b");
		vcpu->next_rip = vcpu->regs[VCPU_REGS_RIP] + 3;
	}
}

static void vcpu_free(struct svm_vcpu *vcpu)
{
	__free_page(pfn_to_page(vcpu->vmcb_pa >> PAGE_SHIFT));
	kfree(vcpu);
}

static int local_cpu_init(int cpu)
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

	per_cpu(local_cpu_data, cpu) = sd;

	return 0;

err:
	kfree(sd);
	return r;
}

static void local_cpu_uninit(int cpu)
{
	struct svm_cpu_data *sd = per_cpu(local_cpu_data, raw_smp_processor_id());

	if (!sd)
		return;

	per_cpu(local_cpu_data, raw_smp_processor_id()) = NULL;
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
		r = local_cpu_init(cpu);
		if (r)
			return r;
	}

	sd = per_cpu(local_cpu_data, me);
	if (!sd) {
		pr_err("%s: svm_data is NULL on %d\n", __func__, me);
		return -EINVAL;
	}

	sd->asid_generation = 1;
	asm volatile("cpuid\n\t" : "=b" (sd->max_asid)
				 : "a" (CPUID_EXT_A_SVM_LOCK_LEAF)
				 : "%rcx","%rdx");
	sd->max_asid--;
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
		local_cpu_uninit(cpu);

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
	
	asm volatile("cli\n");

	r = turn_on_svm();
	if (r)
		goto err;

	for (unsigned int i = 0; i < NR_VCPUS; i++) {

		struct svm_vcpu *vcpu = vcpu_create(i);

		vcpu_run(vcpu);

		vcpu_free(vcpu);
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
