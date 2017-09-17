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
#include <asm/desc.h>
#include <asm/virtext.h>
#include "vmrun.h"

MODULE_LICENSE("Dual BSD/GPL");

static DEFINE_PER_CPU(struct svm_vcpu *, local_vcpu);
static DEFINE_PER_CPU(struct svm_cpu_data *, cpu_data);
static DEFINE_PER_CPU(struct vmcb *, local_vmcb);

static unsigned long iopm_base;

static void svm_enable(void)
{
	int msr_efer_addr  = MSR_EFER_SVM_EN_ADDR;
	int msr_efer_value = 0;

	asm volatile("rdmsr\n\t" : "=A" (msr_efer_value)
	: "c"  (msr_efer_addr)
	:);

	msr_efer_value |= (1 << MSR_EFER_SVM_EN_BIT);

	asm volatile("wrmsr\n\t" :
	: "c" (msr_efer_addr), "A" (msr_efer_value)
	:);
}

static void svm_disable(void)
{
	int msr_efer_addr  = MSR_EFER_SVM_EN_ADDR;
	int msr_efer_value = 0;

	asm volatile("rdmsr\n\t" : "=A" (msr_efer_value)
	: "c"  (msr_efer_addr)
	:);

	msr_efer_value &= ~(1 << MSR_EFER_SVM_EN_BIT);

	asm volatile("wrmsr\n\t" :
	: "c" (msr_efer_addr), "A" (msr_efer_value)
	:);
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
		printk("has_svm: cpuid reports SVM not supported\n");
		return 0;
	}

	//
	// MSR VM CR check (if SVM is disabled)
	//

	msr_vm_cr_addr  = MSR_VM_CR_SVM_DIS_ADDR;

	asm volatile("rdmsr\n\t" : "=a" (msr_vm_cr_value)
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
		printk("has_svm: cpuid reports SVM disabled at BIOS (not unlockable)\n");
	else
		printk("has:svm: cpuid reports SVM disabled at BIOS (with key)\n");

	return 0;
}

static int iopm_allocate(void)
{
	struct page *iopm_pages;
	void *iopm_va;

	iopm_pages = alloc_pages(GFP_KERNEL, IOPM_ALLOC_ORDER);

	if (!iopm_pages)
		return -ENOMEM;

	iopm_va = page_address(iopm_pages);
	memset(iopm_va, 0xff, PAGE_SIZE * (1 << IOPM_ALLOC_ORDER));
	iopm_base = page_to_pfn(iopm_pages) << PAGE_SHIFT;

	printk("iopm_allocate: Allocated I/O permission map");

	return 0;
}

static void iopm_free(void)
{
	__free_pages(pfn_to_page(iopm_base >> PAGE_SHIFT), IOPM_ALLOC_ORDER);
	iopm_base = 0;

	printk("iopm_free: Freed I/O permission map");
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
	struct vmcb_save_area    *save    = &vcpu->vmcb->save;
	unsigned long cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;

	control->intercept |= (1ULL << INTERCEPT_INTR);
	control->intercept |= (1ULL << INTERCEPT_NMI);
	control->intercept |= (1ULL << INTERCEPT_SMI);
	control->intercept |= (1ULL << INTERCEPT_VMRUN);   // Needed?
	control->intercept |= (1ULL << INTERCEPT_VMMCALL);
	control->clean     &= ~(1 << VMCB_INTERCEPTS);

	control->iopm_base_pa  = iopm_base;
	control->msrpm_base_pa = __pa(vcpu->msrpm);
	control->int_ctl       = V_INTR_MASK;

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
	init_sys_seg(&save->tr, SEG_TYPE_AVAIL_TSS64);

	save->rip = 0x0000fff0;
	save->rflags = 2;
	save->dr6 = 0xffff0ff0;

	save->efer = EFER_SVME | EFER_LME | EFER_LMA;
	save->cr0 = cr0 | X86_CR0_PE | X86_CR0_PG | X86_CR0_WP;
	save->cr4 = X86_CR4_PAE;
	control->clean &= ~(1 << VMCB_CR);
	control->clean = 0;

	vcpu->cr0 = cr0;
	vcpu->efer = 0;
	vcpu->hflags |= HF_GIF_MASK;
	vcpu->asid_generation = 0;
	vcpu->regs[VCPU_REGS_RIP] = save->rip;
}

static struct svm_vcpu *vcpu_create(unsigned int id)
{
	struct svm_vcpu *vcpu;
	struct page *vmcb_page;
	struct page *msrpm_pages;
	int me = raw_smp_processor_id();
	int err;

	vcpu = kzalloc(sizeof(struct svm_vcpu), GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	printk("vcpu_create: [%d] Allocated vcpu memory (cpu = %d)\n", id, me);

	vcpu->cpu = me;
	vcpu->vcpu_id = id;

	err = -ENOMEM;
	vmcb_page = alloc_page(GFP_KERNEL);
	if (!vmcb_page)
		goto free_vcpu;

	printk("vcpu_create: [%d] Allocated vmcb memory\n", id);

	msrpm_pages = alloc_pages(GFP_KERNEL, MSRPM_ALLOC_ORDER);
	if (!msrpm_pages)
		goto free_vmcb;

	vcpu->msrpm = page_address(msrpm_pages);
	memset(vcpu->msrpm, 0xff, PAGE_SIZE * (1 << MSRPM_ALLOC_ORDER));

	printk("vcpu_create: [%d] Allocated MSR permissions bitmap memory\n", id);

	vcpu->vmcb = page_address(vmcb_page);
	clear_page(vcpu->vmcb);
	vcpu->vmcb_pa = page_to_pfn(vmcb_page) << PAGE_SHIFT;
	vcpu->asid_generation = 0;
	vmcb_init(vcpu);

	printk("vcpu_create: [%d] Initialized vmcb\n", id);

	vcpu->cpu_data = per_cpu(cpu_data, me);
	per_cpu(local_vcpu, me) = vcpu;
	per_cpu(local_vmcb, me) = vcpu->vmcb;

	return vcpu;

free_vmcb:
	__free_page(vmcb_page);
free_vcpu:
	kfree(vcpu);
out:
	return ERR_PTR(err);
}

struct system_table {
	u16 limit;
	u64 base;
} __attribute__ ((__packed__));

static void vcpu_setup(struct svm_vcpu *vcpu)
{
	struct system_table gdt, idt;
	u64 tr_base, tr_base_lo, tr_base_hi, tr_base_real;
	u32 fs_gs_base_low, fs_gs_base_hi;
	u32 attr_cs, attr_ss, attr_tr;

	asm volatile("movw %%cs, %%ax\n\t"  : "=a" (vcpu->vmcb->save.cs.selector));
	asm volatile("lar %%eax, %%eax\n\t" : "=a" (attr_cs) : "a" (vcpu->vmcb->save.cs.selector));
	asm volatile("movw %%ss, %%ax\n\t"  : "=a" (vcpu->vmcb->save.ss.selector));
	asm volatile("lar %%eax, %%eax\n\t" : "=a" (attr_ss) : "a" (vcpu->vmcb->save.ss.selector));
	asm volatile("movw %%es, %%ax\n\t"  : "=a" (vcpu->vmcb->save.es.selector));
	asm volatile("movw %%ds, %%ax\n\t"  : "=a" (vcpu->vmcb->save.ds.selector));
	asm volatile("movw %%fs, %%ax\n\t"  : "=a" (vcpu->vmcb->save.fs.selector));
	asm volatile("movw %%gs, %%ax\n\t"  : "=a" (vcpu->vmcb->save.gs.selector));
	asm volatile("sldt %%ax\n\t"        : "=a" (vcpu->vmcb->save.ldtr.selector));
	asm volatile("str %%ax\n\t"         : "=a" (vcpu->vmcb->save.tr.selector));
	asm volatile("lar %%eax,%%eax\n\t"  : "=a" (attr_tr) :"a"(vcpu->vmcb->save.tr.selector));
	asm volatile("lsl %%eax, %%eax\n\t" : "=a" (vcpu->vmcb->save.tr.limit));

	vcpu->vmcb->save.cs.limit    = 0xffffffff;
	vcpu->vmcb->save.ss.limit    = 0xffffffff;
	vcpu->vmcb->save.es.limit    = 0xffffffff;
	vcpu->vmcb->save.ds.limit    = 0xffffffff;
	vcpu->vmcb->save.fs.limit    = 0xffffffff;
	vcpu->vmcb->save.gs.limit    = 0xffffffff;
	vcpu->vmcb->save.ldtr.limit  = 0x0;

	vcpu->vmcb->save.tr.attrib   = attr_tr >> 16;
	vcpu->vmcb->save.cs.attrib   = attr_cs >> 16;
	vcpu->vmcb->save.ss.attrib   = attr_ss >> 16;
	vcpu->vmcb->save.es.attrib   = 0x000;
	vcpu->vmcb->save.ds.attrib   = 0x000;
	vcpu->vmcb->save.fs.attrib   = 0x000;
	vcpu->vmcb->save.gs.attrib   = 0x000;
	vcpu->vmcb->save.ldtr.attrib = 0x000;

	asm volatile("sgdt %0\n\t" : : "m" (gdt));
	vcpu->vmcb->save.gdtr.base  = gdt.base;
	vcpu->vmcb->save.gdtr.limit = gdt.limit;

	asm volatile("sidt %0\n\t" : : "m" (idt));
	vcpu->vmcb->save.idtr.base  = idt.base;
	vcpu->vmcb->save.idtr.limit = idt.limit;

	tr_base = gdt.base + vcpu->vmcb->save.tr.selector;

	// SS segment override
	asm volatile("mov %0,%%rax\n\t"
		    ".byte 0x36\n\t"
		    "movq (%%rax), %%rax\n\t" : "=a" (tr_base_lo) : "0" (tr_base));

	tr_base_real = ((tr_base_lo  >> 16) & (0x0ffff)) |
		       (((tr_base_lo >> 32) & 0x000000ff) << 16) |
		       (((tr_base_lo >> 56) & 0xff) << 24);

	// SS segment override for upper32 bits of base in ia32e mode
	asm volatile("mov %0,%%rax\n\t"
		     ".byte 0x36\n\t"
		     "movq 8(%%rax),%%rax\n\t" : "=a" (tr_base_hi) : "0" (tr_base));

	vcpu->vmcb->save.tr.base = tr_base_real | (tr_base_hi << 32);

	asm volatile("movq %%cr0, %%rax\n\t" :"=a"(vcpu->vmcb->save.cr0));
	asm volatile("movq %%cr3, %%rax\n\t" :"=a"(vcpu->vmcb->save.cr3));
	asm volatile("movq %%cr4, %%rax\n\t" :"=a"(vcpu->vmcb->save.cr4));

	asm volatile("mov $0xc0000100, %rcx\n\t");
	asm volatile("rdmsr\n\t" :"=a"(fs_gs_base_low) : :"%rdx");
	asm volatile ("shl $32, %%rdx\n\t" :"=d"(fs_gs_base_hi));
	vcpu->vmcb->save.fs.base = fs_gs_base_hi | fs_gs_base_low;
	asm volatile("mov $0xc0000101, %rcx\n\t");
	asm volatile("rdmsr\n\t" :"=a"(fs_gs_base_low) : :"%rdx");
	asm volatile ("shl $32, %%rdx\n\t" :"=d"(fs_gs_base_hi));
	vcpu->vmcb->save.gs.base = fs_gs_base_hi | fs_gs_base_low;

	vcpu->vmcb->save.dr7 = 0x400;

	asm ("movq %%rsp, %%rax\n\t" :"=a"(vcpu->vmcb->save.rsp));

	asm volatile("pushfq\n\t");
	asm volatile("popq %0\n\t" : "=m"(vcpu->vmcb->save.rflags) : : "memory");

	asm volatile("mov $0x174, %rcx\n\t");
	asm("rdmsr\n\t");
	asm("mov %%rax, %0\n\t" : : "m" (vcpu->vmcb->save.sysenter_cs) : "memory");

	asm volatile("mov $0x175, %rcx\n\t");
	asm("rdmsr\n\t");
	asm("mov %%rax, %0\n\t" : : "m" (vcpu->vmcb->save.sysenter_esp) : "memory");
	asm("or %0, %%rdx\n\t"  : : "m" (vcpu->vmcb->save.sysenter_esp) : "memory");

	asm volatile("mov $0x176, %rcx\n\t");
	asm("rdmsr\n\t");
	asm("mov %%rax, %0\n\t" : : "m" (vcpu->vmcb->save.sysenter_eip) : "memory");
	asm("or %0, %%rdx\n\t"  : : "m" (vcpu->vmcb->save.sysenter_eip) : "memory");

	vcpu->vmcb->control.clean = 0;
}

static void vcpu_run(struct svm_vcpu *vcpu)
{
	int cpu = 0;
	struct svm_cpu_data *cd = NULL;

	printk("vcpu_run: Doing vmrun now\n");

	get_cpu();

	asm volatile("movq $guest_entry_point, %rax\n\t");
	asm volatile("movq %%rax, %0\n\t" : "=r" (vcpu->vmcb->save.rip));
	vcpu->regs[VCPU_REGS_RIP] = vcpu->vmcb->save.rip;

	cpu = raw_smp_processor_id();
	cd  = per_cpu(cpu_data, cpu);

	vcpu->vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;
	if (vcpu->cpu != cpu ||
	    vcpu->asid_generation != cd->asid_generation) {
		if (cd->next_asid > cd->max_asid) {
			++cd->asid_generation;
			cd->next_asid = 1;
			vcpu->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
		}

		vcpu->cpu = cd->cpu;
		vcpu->asid_generation = cd->asid_generation;
		vcpu->vmcb->control.asid = cd->next_asid++;
	}

	asm volatile(
        	INSTR_SVM_CLGI "\n\t"
		"push %%" _ASM_BP " \n\t"
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
		"pop %%" _ASM_BP " \n\t"
        	INSTR_SVM_STGI "\n\t"

		: // No outputs

		: [vcpu]"a"(vcpu),
		  [vmcb]"i"(offsetof(struct svm_vcpu, vmcb_pa)),
		  [rbx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RBX])),
		  [rcx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RCX])),
		  [rdx]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RDX])),
		  [rsi]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RSI])),
		  [rdi]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RDI])),
		  [rbp]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_RBP])),
		  [r8]"i"(offsetof(struct svm_vcpu,  regs[VCPU_REGS_R8])),
		  [r9]"i"(offsetof(struct svm_vcpu,  regs[VCPU_REGS_R9])),
		  [r10]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R10])),
		  [r11]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R11])),
		  [r12]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R12])),
		  [r13]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R13])),
		  [r14]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R14])),
		  [r15]"i"(offsetof(struct svm_vcpu, regs[VCPU_REGS_R15]))

		: "cc", "memory", "rbx", "rcx", "rdx", "rsi", "rdi",
		  "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15");

	printk("vcpu_run: After #vmexit\n");
	asm volatile("jmp vmexit_handler\n\t");
	asm volatile("nop\n\t"); //will never get here

	asm volatile("guest_entry_point:");
	asm volatile(INSTR_SVM_VMMCALL);
	asm volatile("ud2\n\t"); //will never get here

	asm volatile("vmexit_handler:\n");
	printk("vcpu_run: Guest #vmexit Info\n");
	printk("vcpu_run: Code: 0x%x\n", vcpu->vmcb->control.exit_code);
	printk("vcpu_run: Info 1: 0x%llx\n", vcpu->vmcb->control.exit_info_1);
	printk("vcpu_run: Info 2: 0x%llx\n", vcpu->vmcb->control.exit_info_2);

	if (vcpu->vmcb->control.exit_code == SVM_EXIT_ERR) {
		pr_err("vcpu_run: vmrun failed\n");
		return;
	}

	if (vcpu->vmcb->control.exit_code == SVM_EXIT_VMMCALL) {
		printk("vcpu_run: vmrun and vmmcall succeeded\n");
		vcpu->next_rip = vcpu->regs[VCPU_REGS_RIP] + 3;
	}

	put_cpu();
}

static void vcpu_free(struct svm_vcpu *vcpu)
{
	__free_page(pfn_to_page(vcpu->vmcb_pa >> PAGE_SHIFT));
	kfree(vcpu);
}

static int cpu_setup(int cpu)
{
	struct svm_cpu_data *cd;
	int r;

	cd = kzalloc(sizeof(struct svm_cpu_data), GFP_KERNEL);
	if (!cd)
		return -ENOMEM;
	cd->cpu = cpu;
	cd->save_area = alloc_page(GFP_KERNEL);
	r = -ENOMEM;
	if (!cd->save_area)
		goto err;

	per_cpu(cpu_data, cpu) = cd;

	printk("cpu_setup: Setup CPU %d\n", cpu);

	return 0;

err:
	kfree(cd);
	return r;
}

static void cpu_unsetup(int cpu)
{
	struct svm_cpu_data *cd = per_cpu(cpu_data, cpu);

	if (!cd)
		return;

	per_cpu(cpu_data, cpu) = NULL;
	__free_page(cd->save_area);
	kfree(cd);

	printk("cpu_unsetup: Unsetup CPU %d\n", cpu);
}

static void cpu_enable(void *unused)
{
	struct svm_cpu_data *cd;
	struct desc_struct *gdt;
	int me = raw_smp_processor_id();

	if (!has_svm()) {
		printk("cpu_enable: SVM is not supported and enabled on CPU %d\n", me);
	}

	cd = per_cpu(cpu_data, me);

	if (!cd) {
		pr_err("%s: cpu_data is NULL on CPU %d\n", __func__, me);
		return;
	}

	cd->asid_generation = 1;
	asm volatile("cpuid\n\t" : "=b" (cd->max_asid)
				 : "a" (CPUID_EXT_A_SVM_LOCK_LEAF)
				 : "%rcx","%rdx");
	cd->max_asid--;
	cd->next_asid = cd->max_asid + 1;

	printk("cpu_enable: Initialized ASID on CPU %d\n", me);

	// Alternative to the code below for TSS desc registration
	//
	// struct desc_ptr gdt_descr;
	// asm volatile("sgdt %0" : "=m" (gdt_descr));
	// gdt = (struct desc_struct *)gdt_descr.address;

	gdt = this_cpu_ptr(&gdt_page)->gdt;
	cd->tss_desc = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);

	printk("cpu_enable: Registered TSS descriptor on CPU %d\n", me);

	svm_enable();

	printk("cpu_enable: Enabled SVM on CPU %d\n", me);

	asm volatile("wrmsr\n\t" :
				 : "c" (MSR_VM_HSAVE_PA), "A" (page_to_pfn(cd->save_area) << PAGE_SHIFT)
				 :);

	printk("cpu_setup: Registered host save area on CPU %d\n", me);
}

static void cpu_disable(void *unused)
{
	struct svm_cpu_data *cd;
	int me = raw_smp_processor_id();

	cd = per_cpu(cpu_data, me);

	if (cd) {
		// This hangs the machine, no reason why but it does!
		//
		// asm volatile("wrmsr\n\t" :
		// 			    : "c" (MSR_VM_HSAVE_PA), "A" (0)
		// 			    :);

		//printk("cpu_disable: Unregistered host save area on CPU %d\n", me);

		svm_disable();

		printk("cpu_disable: Disabled SVM on CPU %d\n", me);
	}
}

static int vmrun_init(void)
{
	int cpu;
	int r;

	printk("vmrun_init: Initializing AMD-V (SVM) vmrun driver\n");

	if (has_svm()) {
		printk("vmrun_init: SVM is supported and enabled on CPU\n");
	} else {
		printk("vmrun_init: SVM not supported or enabled on CPU, nothing to be done\n");
		goto finish_here;
	}

	r = iopm_allocate();
	if (r)
		goto err;

	for_each_online_cpu(cpu) {
		r = cpu_setup(cpu);
		if (r)
			goto err;
	}

	on_each_cpu(cpu_enable, 0, 1);

	for (unsigned int i = 0; i < NR_VCPUS; i++) {

		struct svm_vcpu *vcpu = vcpu_create(i);
		printk("vmrun_init: Created vcpu %d\n", i);
		vcpu_setup(vcpu);
		printk("vmrun_init: Setup vcpu %d\n", i);
		vcpu_run(vcpu);
		printk("vmrun_init: Run vcpu %d\n", i);
		vcpu_free(vcpu);
		printk("vmrun_init: Freed vcpu %d\n", i);
	}

	on_each_cpu(cpu_disable, 0, 1);

	for_each_online_cpu(cpu)
		cpu_unsetup(cpu);

	iopm_free();

	asm volatile("sti\n\t");

finish_here:
	printk("vmrun_init: Done\n");
	return 0;
err:
	printk("vmrun_init: Error\n");
	return r;
}


static void vmrun_exit(void) {



}

module_init(vmrun_init);
module_exit(vmrun_exit);
