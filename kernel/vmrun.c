//
// =========================================================
// x86 Hardware Assisted Virtualization Demo for AMD-V (SVM)
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
//
// 2. KVM from the Linux kernel
//    (Mostly kvm_main.c, svm.c)
//
// 3. Original Intel VT-x vmlaunch demo
//    (https://github.com/vishmohan/vmlaunch)
//
// 4. Original vmrunsample demo
//    (https://github.com/soulxu/vmrunsample)
//
// Copyright (C) 2017: STROMASYS SA (http://www.stromasys.com)
//
// Authors:
//
// - Elias Kouskoumvekakis <eliask.kousk@stromasys.com>
// - Avi Kivity            <avi@qumranet.com>   (KVM)
// - Yaniv Kamay           <yaniv@qumranet.com> (KVM)
//
// This work is licensed under the terms of the GNU GPL, version 2.
// See the LICENSE file in the top-level directory.
//
// ===============================================================
//
// Sample Run (TODO: Update)
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
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/desc.h>
#include <asm/virtext.h>
#include "vmrun.h"
#include "../user/vmrun.h"

MODULE_AUTHOR("STROMASYS");
MODULE_LICENSE("GPL");

static DEFINE_PER_CPU(struct vmrun_vcpu *, local_vcpu);
static DEFINE_PER_CPU(struct vmrun_cpu_data *, cpu_data);
static DEFINE_PER_CPU(struct vmcb *, local_vmcb);

static DEFINE_RAW_SPINLOCK(vmrun_count_lock);
static int vmrun_usage_count;
static atomic_t cpu_enable_failed;
static __read_mostly struct preempt_ops vmrun_preempt_ops;
static cpumask_var_t cpus_enabled;
static unsigned long iopm_base;

static inline u16 read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static inline void load_ldt(u16 sel)
{
	asm("lldt %0" : : "rm"(sel));
}

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

static void vmcb_init(struct vmrun_vcpu *vcpu)
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

struct system_table {
	u16 limit;
	u64 base;
} __attribute__ ((__packed__));

static void vcpu_setup(struct vmrun_vcpu *vcpu)
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

static void vcpu_run(struct vmrun_vcpu *vcpu)
{
	int cpu = 0;
	struct vmrun_cpu_data *cd = NULL;

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
	[vmcb]"i"(offsetof(struct vmrun_vcpu, vmcb_pa)),
	[rbx]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_RBX])),
	[rcx]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_RCX])),
	[rdx]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_RDX])),
	[rsi]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_RSI])),
	[rdi]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_RDI])),
	[rbp]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_RBP])),
	[r8]"i"(offsetof(struct vmrun_vcpu,  regs[VCPU_REGS_R8])),
	[r9]"i"(offsetof(struct vmrun_vcpu,  regs[VCPU_REGS_R9])),
	[r10]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_R10])),
	[r11]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_R11])),
	[r12]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_R12])),
	[r13]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_R13])),
	[r14]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_R14])),
	[r15]"i"(offsetof(struct vmrun_vcpu, regs[VCPU_REGS_R15]))

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

static void vcpu_free(struct vmrun_vcpu *vcpu)
{
	__free_page(pfn_to_page(vcpu->vmcb_pa >> PAGE_SHIFT));
	kfree(vcpu);
}

static void svm_vcpu_load(struct vmrun_vcpu *vcpu, int cpu)
{
	if (unlikely(cpu != vcpu->cpu)) {
		vcpu->asid_generation = 0;
		vcpu->vmcb->control.clean = 0;
	}

	rdmsrl(MSR_GS_BASE, vcpu->host.gs_base);
	savesegment(fs, vcpu->host.fs);
	savesegment(gs, vcpu->host.gs);
	vcpu->host.ldt = read_ldt();
}

static void svm_vcpu_put(struct vmrun_vcpu *vcpu)
{
	load_ldt(vcpu->host.ldt);
	loadsegment(fs, vcpu->host.fs);
	wrmsrl(MSR_KERNEL_GS_BASE, current->thread.gsbase);
	load_gs_index(vcpu->host.gs);
}

int vcpu_load(struct vmrun_vcpu *vcpu)
{
	int cpu;

	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);
	svm_vcpu_load(vcpu, cpu);
	put_cpu();

	return 0;
}

void vcpu_put(struct vmrun_vcpu *vcpu)
{
	preempt_disable();
	svm_vcpu_put(vcpu);
	preempt_notifier_unregister(&vcpu->preempt_notifier);
	preempt_enable();
	mutex_unlock(&vcpu->mutex);
}

static void svm_vcpu_create(struct vmrun_vcpu *vcpu)
{
	struct page *vmcb_page;
	struct page *msrpm_pages;
	int me = raw_smp_processor_id();
	int err;

	vcpu = kzalloc(sizeof(struct vmrun_vcpu), GFP_KERNEL);
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

/*
 * Free any memory in @free but not in @dont.
 */
static void vmrun_free_physmem_slot(struct vmrun_memory_slot *free,
				  struct vmrun_memory_slot *dont)
{
	int i;

	if (!dont || free->phys_mem != dont->phys_mem)
		if (free->phys_mem) {
			for (i = 0; i < free->npages; ++i)
				__free_page(free->phys_mem[i]);
			vfree(free->phys_mem);
		}

	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		vfree(free->dirty_bitmap);

	free->phys_mem = 0;
	free->npages = 0;
	free->dirty_bitmap = 0;
}

static void vmrun_free_physmem(struct vmrun *vmrun)
{
	int i;

	for (i = 0; i < vmrun->nmemslots; ++i)
		vmrun_free_physmem_slot(&vmrun->memslots[i], 0);
}

static void vmrun_free_vcpu(struct vmrun_vcpu *vcpu)
{
	vcpu_free(vcpu);
	//vmrun_mmu_destroy(vcpu);
}

static void vmrun_free_vcpus(struct vmrun *vmrun)
{
	unsigned int i;

	for (i = 0; i < VMRUN_MAX_VCPUS; ++i)
		vmrun_free_vcpu(&vmrun->vcpus[i]);
}

static int vmrun_dev_ioctl_vcpu_create(struct vmrun *vmrun, int n) {
	int r;
	struct vmrun_vcpu *vcpu;

	r = -EINVAL;
	if (n < 0 || n >= VMRUN_MAX_VCPUS)
		goto out;

	vcpu = &vmrun->vcpus[n];

	mutex_lock(&vcpu->mutex);

	if (vcpu->vmcb) {
		mutex_unlock(&vcpu->mutex);
		return -EEXIST;
	}

	vcpu->cpu = -1;  /* First load will set up TR */
	vcpu->vmrun = vmrun;
	r = svm_vcpu_create(vcpu);
	if (r < 0)
		goto out_free_vcpus;

	vcpu_load(vcpu);

	r = vcpu_setup(vcpu);
	if (r >= 0)
		r = vmrun_mmu_init(vcpu);

	vcpu_put(vcpu);

	if (r < 0)
		goto out_free_vcpus;

	return 0;

	out_free_vcpus:
	vmrun_free_vcpu(vcpu);
	mutex_unlock(&vcpu->mutex);
	out:
	return r;
}

static int vmrun_dev_ioctl_vcpu_run(struct vmrun *vmrun, struct vmrun_run *run)
{
	struct vmrun_vcpu *vcpu;
	int r;

	if (run->vcpu < 0 || run->vcpu >= VMRUN_MAX_VCPUS)
		return -EINVAL;

	vcpu = vcpu_load(vmrun, run->vcpu);

	if (!vcpu)
		return -ENOENT;

	if (run->emulated) {
		svm_skip_emulated_instruction(vcpu);
		run->emulated = 0;
	}

	if (run->mmio_completed) {
		memcpy(vcpu->mmio_data, run->mmio.data, 8);
		vcpu->mmio_read_completed = 1;
	}

	vcpu->mmio_needed = 0;

	r = vcpu_run(vcpu, run);

	vcpu_put(vcpu);

	return r;
}

static int vmrun_dev_ioctl_get_regs(struct vmrun *vmrun, struct vmrun_regs *regs)
{
	struct vmrun_vcpu *vcpu;

	if (regs->vcpu < 0 || regs->vcpu >= VMRUN_MAX_VCPUS)
		return -EINVAL;

	vcpu = vcpu_load(vmrun, regs->vcpu);

	if (!vcpu)
		return -ENOENT;

	svm_cache_regs(vcpu);

	regs->rax = vcpu->regs[VCPU_REGS_RAX];
	regs->rbx = vcpu->regs[VCPU_REGS_RBX];
	regs->rcx = vcpu->regs[VCPU_REGS_RCX];
	regs->rdx = vcpu->regs[VCPU_REGS_RDX];
	regs->rsi = vcpu->regs[VCPU_REGS_RSI];
	regs->rdi = vcpu->regs[VCPU_REGS_RDI];
	regs->rsp = vcpu->regs[VCPU_REGS_RSP];
	regs->rbp = vcpu->regs[VCPU_REGS_RBP];
	regs->r8 = vcpu->regs[VCPU_REGS_R8];
	regs->r9 = vcpu->regs[VCPU_REGS_R9];
	regs->r10 = vcpu->regs[VCPU_REGS_R10];
	regs->r11 = vcpu->regs[VCPU_REGS_R11];
	regs->r12 = vcpu->regs[VCPU_REGS_R12];
	regs->r13 = vcpu->regs[VCPU_REGS_R13];
	regs->r14 = vcpu->regs[VCPU_REGS_R14];
	regs->r15 = vcpu->regs[VCPU_REGS_R15];
	regs->rip = vcpu->rip;
	regs->rflags = svm_get_rflags(vcpu);

	/*
	 * Don't leak debug flags in case they were set for guest debugging
	 */
	if (vcpu->guest_debug.enabled && vcpu->guest_debug.singlestep)
		regs->rflags &= ~(X86_EFLAGS_TF | X86_EFLAGS_RF);

	vcpu_put(vcpu);

	return 0;
}

static int vmrun_dev_ioctl_set_regs(struct vmrun *vmrun, struct vmrun_regs *regs)
{
	struct vmrun_vcpu *vcpu;

	if (regs->vcpu < 0 || regs->vcpu >= VMRUN_MAX_VCPUS)
		return -EINVAL;

	vcpu = vcpu_load(vmrun, regs->vcpu);

	if (!vcpu)
		return -ENOENT;

	vcpu->regs[VCPU_REGS_RAX] = regs->rax;
	vcpu->regs[VCPU_REGS_RBX] = regs->rbx;
	vcpu->regs[VCPU_REGS_RCX] = regs->rcx;
	vcpu->regs[VCPU_REGS_RDX] = regs->rdx;
	vcpu->regs[VCPU_REGS_RSI] = regs->rsi;
	vcpu->regs[VCPU_REGS_RDI] = regs->rdi;
	vcpu->regs[VCPU_REGS_RSP] = regs->rsp;
	vcpu->regs[VCPU_REGS_RBP] = regs->rbp;
	vcpu->regs[VCPU_REGS_R8]  = regs->r8;
	vcpu->regs[VCPU_REGS_R9]  = regs->r9;
	vcpu->regs[VCPU_REGS_R10] = regs->r10;
	vcpu->regs[VCPU_REGS_R11] = regs->r11;
	vcpu->regs[VCPU_REGS_R12] = regs->r12;
	vcpu->regs[VCPU_REGS_R13] = regs->r13;
	vcpu->regs[VCPU_REGS_R14] = regs->r14;
	vcpu->regs[VCPU_REGS_R15] = regs->r15;

	vcpu->rip = regs->rip;

	svm_set_rflags(vcpu, regs->rflags);
	svm_decache_regs(vcpu);

	vcpu_put(vcpu);

	return 0;
}

static void get_segment(struct vmrun_vcpu *vcpu,
			struct vmrun_segment *var, int seg)
{
	return vmrun_arch_ops->get_segment(vcpu, var, seg);
}

static int vmrun_dev_ioctl_get_sregs(struct vmrun *vmrun, struct vmrun_sregs *sregs)
{
	struct vmrun_vcpu *vcpu;
	struct descriptor_table dt;

	if (sregs->vcpu < 0 || sregs->vcpu >= VMRUN_MAX_VCPUS)
		return -EINVAL;

	vcpu = vcpu_load(vmrun, sregs->vcpu);

	if (!vcpu)
		return -ENOENT;

	get_segment(vcpu, &sregs->cs,  VCPU_SREG_CS);
	get_segment(vcpu, &sregs->ds,  VCPU_SREG_DS);
	get_segment(vcpu, &sregs->es,  VCPU_SREG_ES);
	get_segment(vcpu, &sregs->fs,  VCPU_SREG_FS);
	get_segment(vcpu, &sregs->gs,  VCPU_SREG_GS);
	get_segment(vcpu, &sregs->ss,  VCPU_SREG_SS);
	get_segment(vcpu, &sregs->tr,  VCPU_SREG_TR);
	get_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	get_idt(vcpu, &dt);
	sregs->idt.limit = dt.limit;
	sregs->idt.base  = dt.base;
	get_gdt(vcpu, &dt);
	sregs->gdt.limit = dt.limit;
	sregs->gdt.base  = dt.base;
	sregs->cr0       = vcpu->cr0;
	sregs->cr2       = vcpu->cr2;
	sregs->cr3       = vcpu->cr3;
	sregs->cr4       = vcpu->cr4;
	sregs->cr8       = vcpu->cr8;
	sregs->efer      = vcpu->shadow_efer;
	sregs->apic_base = vcpu->apic_base;

	memcpy(sregs->interrupt_bitmap,
	       vcpu->irq_pending,
	       sizeof sregs->interrupt_bitmap);

	vcpu_put(vcpu);

	return 0;
}

static void set_segment(struct vmrun_vcpu *vcpu,
			struct vmrun_segment *var, int seg)
{
	return vmrun_arch_ops->set_segment(vcpu, var, seg);
}

static int vmrun_dev_ioctl_set_sregs(struct vmrun *vmrun, struct vmrun_sregs *sregs)
{
	struct vmrun_vcpu *vcpu;
	int mmu_reset_needed = 0;
	int i;
	struct descriptor_table dt;

	if (sregs->vcpu < 0 || sregs->vcpu >= VMRUN_MAX_VCPUS)
		return -EINVAL;

	vcpu = vcpu_load(vmrun, sregs->vcpu);

	if (!vcpu)
		return -ENOENT;

	set_segment(vcpu, &sregs->cs,  VCPU_SREG_CS);
	set_segment(vcpu, &sregs->ds,  VCPU_SREG_DS);
	set_segment(vcpu, &sregs->es,  VCPU_SREG_ES);
	set_segment(vcpu, &sregs->fs,  VCPU_SREG_FS);
	set_segment(vcpu, &sregs->gs,  VCPU_SREG_GS);
	set_segment(vcpu, &sregs->ss,  VCPU_SREG_SS);
	set_segment(vcpu, &sregs->tr,  VCPU_SREG_TR);
	set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	dt.limit = sregs->idt.limit;
	dt.base = sregs->idt.base;
	set_idt(vcpu, &dt);
	dt.limit = sregs->gdt.limit;
	dt.base = sregs->gdt.base;
	set_gdt(vcpu, &dt);

	vcpu->cr2 = sregs->cr2;
	mmu_reset_needed |= vcpu->cr3 != sregs->cr3;
	vcpu->cr3 = sregs->cr3;
	vcpu->cr8 = sregs->cr8;

	mmu_reset_needed |= vcpu->shadow_efer != sregs->efer;

	set_efer(vcpu, sregs->efer);

	vcpu->apic_base = sregs->apic_base;

	mmu_reset_needed |= vcpu->cr0 != sregs->cr0;
	set_cr0_no_modeswitch(vcpu, sregs->cr0);

	mmu_reset_needed |= vcpu->cr4 != sregs->cr4;
	set_cr4(vcpu, sregs->cr4);

	if (mmu_reset_needed)
		vmrun_mmu_reset_context(vcpu);

	memcpy(vcpu->irq_pending,
	       sregs->interrupt_bitmap,
	       sizeof vcpu->irq_pending);

	vcpu->irq_summary = 0;

	for (i = 0; i < NR_IRQ_WORDS; ++i)
		if (vcpu->irq_pending[i])
			__set_bit(i, &vcpu->irq_summary);

	vcpu_put(vcpu);

	return 0;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 */
static int vmrun_dev_ioctl_set_memory_region(struct vmrun *vmrun,
					     struct vmrun_memory_region *mem)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct vmrun_memory_slot *memslot;
	struct vmrun_memory_slot old, new;
	int memory_config_version;

	r = -EINVAL;

	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;

	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;

	if (mem->slot >= VMRUN_MEMORY_SLOTS)
		goto out;

	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	memslot  = &vmrun->memslots[mem->slot];
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages   = mem->memory_size >> PAGE_SHIFT;

	if (!npages)
		mem->flags &= ~VMRUN_MEM_LOG_DIRTY_PAGES;

raced:
	spin_lock(&vmrun->lock);

	memory_config_version = vmrun->memory_config_version;
	new = old = *memslot;

	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	/* Disallow changing a memory slot's size. */
	r = -EINVAL;
	if (npages && old.npages && npages != old.npages)
		goto out_unlock;

	/* Check for overlaps */
	r = -EEXIST;
	for (i = 0; i < VMRUN_MEMORY_SLOTS; ++i) {
		struct vmrun_memory_slot *s = &vmrun->memslots[i];

		if (s == memslot)
			continue;
		if (!((base_gfn + npages <= s->base_gfn) ||
		      (base_gfn >= s->base_gfn + s->npages)))
			goto out_unlock;
	}

	/*
	 * Do memory allocations outside lock.  memory_config_version will
	 * detect any races.
	 */
	spin_unlock(&vmrun->lock);

	/* Deallocate if slot is being removed */
	if (!npages)
		new.phys_mem = 0;

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & VMRUN_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = 0;

	r = -ENOMEM;

	/* Allocate if a slot is being created */
	if (npages && !new.phys_mem) {
		new.phys_mem = vmalloc(npages * sizeof(struct page *));

		if (!new.phys_mem)
			goto out_free;

		memset(new.phys_mem, 0, npages * sizeof(struct page *));

		for (i = 0; i < npages; ++i) {
			new.phys_mem[i] = alloc_page(GFP_HIGHUSER
						     | __GFP_ZERO);

			if (!new.phys_mem[i])
				goto out_free;
		}
	}

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & VMRUN_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		unsigned dirty_bytes = ALIGN(npages, BITS_PER_LONG) / 8;

		new.dirty_bitmap = vmalloc(dirty_bytes);

		if (!new.dirty_bitmap)
			goto out_free;

		memset(new.dirty_bitmap, 0, dirty_bytes);
	}

	spin_lock(&vmrun->lock);

	if (memory_config_version != vmrun->memory_config_version) {
		spin_unlock(&vmrun->lock);
		vmrun_free_physmem_slot(&new, &old);
		goto raced;
	}

	r = -EAGAIN;
	if (vmrun->busy)
		goto out_unlock;

	if (mem->slot >= vmrun->nmemslots)
		vmrun->nmemslots = mem->slot + 1;

	*memslot = new;
	++vmrun->memory_config_version;

	spin_unlock(&vmrun->lock);

	for (i = 0; i < VMRUN_MAX_VCPUS; ++i) {
		struct vmrun_vcpu *vcpu;

		vcpu = vcpu_load(vmrun, i);

		if (!vcpu)
			continue;
		vmrun_mmu_reset_context(vcpu);

		vcpu_put(vcpu);
	}

	vmrun_free_physmem_slot(&old, &new);
	return 0;

out_unlock:
	spin_unlock(&vmrun->lock);

out_free:
	vmrun_free_physmem_slot(&new, &old);

out:
	return r;
}

static int vmrun_dev_open(struct inode *inode, struct file *filp)
{
	struct vmrun *vmrun = kzalloc(sizeof(struct vmrun), GFP_KERNEL);
	int i;

	if (!vmrun)
		return -ENOMEM;

	spin_lock_init(&vmrun->lock);

	INIT_LIST_HEAD(&vmrun->active_mmu_pages);

	for (i = 0; i < VMRUN_MAX_VCPUS; ++i) {
		struct vmrun_vcpu *vcpu = &vmrun->vcpus[i];

		mutex_init(&vcpu->mutex);
		vcpu->mmu.root_hpa = INVALID_PAGE;
		INIT_LIST_HEAD(&vcpu->free_pages);
	}

	filp->private_data = vmrun;

	return 0;
}

static int vmrun_dev_release(struct inode *inode, struct file *filp)
{
	struct vmrun *vmrun = filp->private_data;

	vmrun_free_vcpus(vmrun);
	vmrun_free_physmem(vmrun);
	kfree(vmrun);
	return 0;
}

static long vmrun_dev_ioctl(struct file *filp,
			    unsigned int ioctl,
			    unsigned long arg)
{
	struct vmrun *vmrun = filp->private_data;
	int r = -EINVAL;

	switch (ioctl) {
		case VMRUN_VCPU_CREATE: {
			r = vmrun_dev_ioctl_vcpu_create(vmrun, arg);
			if (r)
				goto out;
			break;
		}

		case VMRUN_VCPU_RUN: {
			struct vmrun_run run;

			r = -EFAULT;
			if (copy_from_user(&run, (void *)arg, sizeof run))
				goto out;
			r = vmrun_dev_ioctl_vcpu_run(vmrun, &run);
			if (r < 0)
				goto out;
			r = -EFAULT;
			if (copy_to_user((void *)arg, &run, sizeof run))
				goto out;
			r = 0;
			break;
		}
		
		case VMRUN_GET_REGS: {
			struct vmrun_regs regs;

			r = -EFAULT;
			if (copy_from_user(&regs, (void *)arg, sizeof regs))
				goto out;
			r = vmrun_dev_ioctl_get_regs(vmrun, &regs);
			if (r)
				goto out;
			r = -EFAULT;
			if (copy_to_user((void *)arg, &regs, sizeof regs))
				goto out;
			r = 0;
			break;
		}
		
		case VMRUN_SET_REGS: {
			struct vmrun_regs regs;

			r = -EFAULT;
			if (copy_from_user(&regs, (void *)arg, sizeof regs))
				goto out;
			r = vmrun_dev_ioctl_set_regs(vmrun, &regs);
			if (r)
				goto out;
			r = 0;
			break;
		}
		
		case VMRUN_GET_SREGS: {
			struct vmrun_sregs sregs;

			r = -EFAULT;
			if (copy_from_user(&sregs, (void *)arg, sizeof sregs))
				goto out;
			r = vmrun_dev_ioctl_get_sregs(vmrun, &sregs);
			if (r)
				goto out;
			r = -EFAULT;
			if (copy_to_user((void *)arg, &sregs, sizeof sregs))
				goto out;
			r = 0;
			break;
		}
		
		case VMRUN_SET_SREGS: {
			struct vmrun_sregs sregs;

			r = -EFAULT;
			if (copy_from_user(&sregs, (void *)arg, sizeof sregs))
				goto out;
			r = vmrun_dev_ioctl_set_sregs(vmrun, &sregs);
			if (r)
				goto out;
			r = 0;
			break;
		}

		case VMRUN_SET_USER_MEMORY_REGION: {
			struct vmrun_memory_region mem;

			r = -EFAULT;
			if (copy_from_user(&mem, (void *)arg, sizeof mem))
				goto out;
			r = vmrun_dev_ioctl_set_memory_region(vmrun, &mem);
			if (r)
				goto out;
			break;
		}

		default:
			;
	}

out:
	return r;
}

//static struct page *vmrun_dev_nopage(struct vm_area_struct *vma,
//				   unsigned long address,
//				   int *type)
//{
//	struct vmrun *vmrun = vma->vm_file->private_data;
//	unsigned long pgoff;
//	struct vmrun_memory_slot *slot;
//	struct page *page;
//
//	*type = VM_FAULT_MINOR;
//	pgoff = ((address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
//	slot = gfn_to_memslot(vmrun, pgoff);
//	if (!slot)
//		return NOPAGE_SIGBUS;
//	page = gfn_to_page(slot, pgoff);
//	if (!page)
//		return NOPAGE_SIGBUS;
//	get_page(page);
//	return page;
//}
//
//static struct vm_operations_struct vmrun_dev_vm_ops = {
//	.nopage = vmrun_dev_nopage,
//};
//
//static int vmrun_dev_mmap(struct file *file, struct vm_area_struct *vma)
//{
//	vma->vm_ops = &vmrun_dev_vm_ops;
//	return 0;
//}

static struct file_operations vmrun_chardev_ops = {
	.open		= vmrun_dev_open,
	.release        = vmrun_dev_release,
	.unlocked_ioctl = vmrun_dev_ioctl,
	.compat_ioctl   = vmrun_dev_ioctl,
	.llseek		= noop_llseek,
	//.mmap           = vmrun_dev_mmap,
};

static struct miscdevice vmrun_dev = {
	MISC_DYNAMIC_MINOR,
	"vmrun",
	&vmrun_chardev_ops,
};

static inline
struct vmrun_vcpu *preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct vmrun_vcpu, preempt_notifier);
}

static void vmrun_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct vmrun_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	if (vcpu->preempted)
		vcpu->preempted = false;

	svm_vcpu_load(vcpu, cpu);
}

static void vmrun_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	struct vmrun_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	if (current->state == TASK_RUNNING)
		vcpu->preempted = true;

	svm_vcpu_put(vcpu);
}

static int cpu_enable()
{
	struct vmrun_cpu_data *cd;
	struct desc_struct *gdt;
	int me = raw_smp_processor_id();
	uint64_t efer;

	// TODO: Move the check to a function
	rdmsrl(MSR_EFER, efer);
	if (efer & EFER_SVME)
		return -EBUSY;

	if (!has_svm()) {
		printk("cpu_enable: SVM is not supported and enabled on CPU %d\n", me);
		return -EINVAL;
	}

	cd = per_cpu(cpu_data, me);

	if (!cd) {
		pr_err("%s: cpu_data is NULL on CPU %d\n", __func__, me);
		return -EINVAL;
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

static void cpu_enable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	if (cpumask_test_cpu(cpu, cpus_enabled))
		return;

	cpumask_set_cpu(cpu, cpus_enabled);

	r = cpu_enable();

	if (r) {
		cpumask_clear_cpu(cpu, cpus_enabled);
		atomic_inc(&cpu_enable_failed);
		pr_info("cpu_enable_nolock: enabling virtualization on CPU %d failed\n", cpu);
	}
}

static int vmrun_cpu_enable(unsigned int cpu)
{
	raw_spin_lock(&vmrun_count_lock);

	if (vmrun_usage_count)
		cpu_enable_nolock(NULL);

	raw_spin_unlock(&vmrun_count_lock);

	return 0;
}

static void cpu_disable()
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_enabled))
		return;
	cpumask_clear_cpu(cpu, cpus_enabled);

	// This hangs the machine, no reason why but it does!
	// TODO: Retest with new changes
	//
	// asm volatile("wrmsr\n\t" :
	// 			    : "c" (MSR_VM_HSAVE_PA), "A" (0)
	// 			    :);

	// printk("cpu_disable: Unregistered host save area on CPU %d\n", me);

	svm_disable();

	printk("cpu_disable: Disabled SVM on CPU %d\n", cpu);
}

static void cpu_disable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_enabled))
		return;

	cpumask_clear_cpu(cpu, cpus_enabled);

	cpu_disable();
}

static int vmrun_cpu_disable(unsigned int cpu)
{
	raw_spin_lock(&vmrun_count_lock);

	if (vmrun_usage_count)
		cpu_disable_nolock(NULL);

	raw_spin_unlock(&vmrun_count_lock);

	return 0;
}

static int vmrun_cpu_setup(int cpu)
{
	struct vmrun_cpu_data *cd;
	int r;

	cd = kzalloc(sizeof(struct vmrun_cpu_data), GFP_KERNEL);
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

static void vmrun_cpu_unsetup(int cpu)
{
	// Called by for_each_*_cpu thus cpu = raw_smp_processor_id()
	// and we can use either. KVM uses the latter for non-obvious reasons

	struct vmrun_cpu_data *cd = per_cpu(cpu_data, raw_smp_processor_id());

	if (!cd)
		return;

	per_cpu(cpu_data, raw_smp_processor_id()) = NULL;
	__free_page(cd->save_area);
	kfree(cd);

	printk("cpu_unsetup: Unsetup CPU %d\n", cpu);
}

static int vmrun_init(void)
{
	int cpu;
	int r;

	printk("vmrun_init: Initializing AMD-V (SVM) vmrun driver\n");

	if (!zalloc_cpumask_var(&cpus_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_fail;
	}

	r = iopm_allocate();
	if (r)
		goto out_free_cpumask;

	for_each_possible_cpu(cpu) {
		r = vmrun_cpu_setup(cpu);
		if (r)
			goto out_free_iopm;
	}

	r = cpuhp_setup_state_nocalls(CPUHP_AP_KVM_STARTING, "vmrun/cpu:starting",
				      vmrun_cpu_enable, vmrun_cpu_disable);
	if (r)
		goto out_free_cpus;

	vmrun_chardev_ops.owner = THIS_MODULE;

	r = misc_register(&vmrun_dev);
	if (r) {
		printk (KERN_ERR "vmrun_init: Misc device register failed\n");
		goto out_free_hp;
	}

	vmrun_preempt_ops.sched_in = vmrun_sched_in;
	vmrun_preempt_ops.sched_out = vmrun_sched_out;

	printk("vmrun_init: Done\n");
	
	return r;

out_free_hp:
	cpuhp_remove_state_nocalls(CPUHP_AP_KVM_STARTING);

out_free_cpus:
	for_each_possible_cpu(cpu)
		vmrun_cpu_unsetup(cpu);

out_free_iopm:
	iopm_free();

out_free_cpumask:
	free_cpumask_var(cpus_enabled);
	
out_fail:
	printk("vmrun_init: Error\n");
	return r;
}

static void vmrun_exit(void)
{
	int cpu;

	misc_deregister(&vmrun_dev);

	cpuhp_remove_state_nocalls(CPUHP_AP_KVM_STARTING);

	on_each_cpu(cpu_disable_nolock, NULL, 1);

	for_each_possible_cpu(cpu)
		vmrun_cpu_unsetup(cpu);

	iopm_free();

	free_cpumask_var(cpus_enabled);

	printk("vmrun_exit: Done\n");
}

module_init(vmrun_init);
module_exit(vmrun_exit);
