//
// =========================================================
// x86 Hardware Assisted Virtualization Demo for AMD-V (SVM)
// =========================================================
//
// Description: A minimal (formerly basic!) driver that walks
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
//    (Mostly vmrun_main.c, mmu.c, x86.c svm.c)
//
// 3. Original Intel VT-x vmlaunch demo
//    (https://github.com/vishmohan/vmlaunch)
//
// 4. Original kvmsample demo
//    (https://github.com/soulxu/kvmsample)
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
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/context_tracking.h>
#include <asm/desc.h>
#include <asm/virtext.h>
#include <asm/svm.h>

#include "mmu.h"
#include "page_track.h"
#include "vmrun.h"
#include "../user/vmrun.h"

MODULE_AUTHOR("STROMASYS");
MODULE_LICENSE("GPL");

DEFINE_SPINLOCK(vmrun_lock);
static DEFINE_RAW_SPINLOCK(vmrun_count_lock);
LIST_HEAD(vm_list);

static cpumask_var_t cpus_enabled;
static int vmrun_usage_count;
static atomic_t cpu_enable_failed;

struct kmem_cache *vmrun_vcpu_cache;

static __read_mostly struct preempt_ops vmrun_preempt_ops;

static unsigned long iopm_base;

static bool npt_enabled = false;

static DEFINE_PER_CPU(struct vmrun_vcpu *, local_vcpu);
static DEFINE_PER_CPU(struct vmrun_cpu_data *, local_cpu_data);
static DEFINE_PER_CPU(struct vmcb *, local_vmcb);

static inline u16 vmrun_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static inline void vmrun_load_ldt(u16 sel)
{
	asm("lldt %0" : : "rm"(sel));
}

static void vmrun_svm_enable(void)
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

static void vmrun_svm_disable(void)
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

static int vmrun_svm_check(void)
{
	int msr_efer_addr  = MSR_EFER_SVM_EN_ADDR;
	int msr_efer_value = 0;

	asm volatile("rdmsr\n\t" : "=A" (msr_efer_value)
				 : "c"  (msr_efer_addr)
				 :);

	msr_efer_value &= ;

	return (msr_efer_value & (1 << MSR_EFER_SVM_EN_BIT));
}

static int vmrun_has_svm(void)
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

static int vmrun_iopm_allocate(void)
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

static void vmrun_iopm_free(void)
{
	__free_pages(pfn_to_page(iopm_base >> PAGE_SHIFT), IOPM_ALLOC_ORDER);
	iopm_base = 0;

	printk("iopm_free: Freed I/O permission map");
}

static inline void vmrun_set_cr_intercept(struct vmrun_vcpu *vcpu, int bit)
{
	vcpu->vmcb->control.intercept_cr |= (1U << bit);
	vcpu->vmcb->control.clean        &= ~(1 << VMCB_INTERCEPTS);
}

static inline void vmrun_clr_cr_intercept(struct vmrun_vcpu *vcpu, int bit)
{
	vcpu->vmcb->control.intercept_cr &= ~(1U << bit);
	vcpu->vmcb->control.clean        &= ~(1 << VMCB_INTERCEPTS);
}

static inline bool vmrun_is_cr_intercept(struct vmrun_vcpu *vcpu, int bit)
{
	return vcpu->vmcb->control.intercept_cr & (1U << bit);
}

static void vmrun_update_cr0_intercept(struct vmrun_vcpu *vcpu)
{
	ulong gcr0 = vcpu->cr0;
	u64 *hcr0  = &vcpu->vmcb->save.cr0;

	*hcr0 = (*hcr0 & ~VMRUN_CR0_SELECTIVE_MASK)
		| (gcr0 & VMRUN_CR0_SELECTIVE_MASK);

	vcpu->vmcb->control.clean  &= ~(1 << VMCB_CR);

	if (gcr0 == *hcr0) {
		vmrun_clr_cr_intercept(vcpu, INTERCEPT_CR0_READ);
		vmrun_clr_cr_intercept(vcpu, INTERCEPT_CR0_WRITE);
	} else {
		vmrun_set_cr_intercept(vcpu, INTERCEPT_CR0_READ);
		vmrun_set_cr_intercept(vcpu, INTERCEPT_CR0_WRITE);
	}
}

static void vmrun_set_cr0(struct vmrun_vcpu *vcpu, unsigned long cr0)
{
	if (vcpu->efer & EFER_LME) {
		if (!likely(vmrun_read_cr0_bits(vcpu, X86_CR0_PG)) && (cr0 & X86_CR0_PG)) {
			vcpu->efer |= EFER_LMA;
			vcpu->vmcb->save.efer |= EFER_LMA | EFER_LME;
		}

		if (likely(vmrun_read_cr0_bits(vcpu, X86_CR0_PG)) && !(cr0 & X86_CR0_PG)) {
			vcpu->efer &= ~EFER_LMA;
			vcpu->vmcb->save.efer &= ~(EFER_LMA | EFER_LME);
		}
	}

	vcpu->cr0 = cr0;

	if (!npt_enabled)
		cr0 |= X86_CR0_PG | X86_CR0_WP;

	/*
	 * re-enable caching here because the QEMU bios
	 * does not do it - this results in some delay at
	 * reboot
	 */
//	if (vmrun_check_has_quirk(vcpu->vmrun, VMRUN_X86_QUIRK_CD_NW_CLEARED))
//		cr0 &= ~(X86_CR0_CD | X86_CR0_NW);

	vcpu->vmcb->save.cr0        = cr0;
	vcpu->vmcb->control.clean  &= ~(1 << VMCB_CR);

	vmrun_update_cr0_intercept(vcpu);
}

static void vmrun_flush_tlb(struct vmrun_vcpu *vcpu)
{
	if (static_cpu_has(X86_FEATURE_FLUSHBYASID))
		vcpu->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;
	else
		vcpu->asid_generation--;
}

static int vmrun_set_cr4(struct vmrun_vcpu *vcpu, unsigned long cr4)
{
	unsigned long host_cr4_mce = cr4_read_shadow() & X86_CR4_MCE;
	unsigned long old_cr4      = vcpu->vmcb->save.cr4;

	if (cr4 & X86_CR4_VMXE)
		return 1;

	if (npt_enabled && ((old_cr4 ^ cr4) & X86_CR4_PGE))
		vmrun_flush_tlb(vcpu);

	vcpu->cr4 = cr4;

	if (!npt_enabled)
		cr4 |= X86_CR4_PAE;

	cr4 |= host_cr4_mce;

	vcpu->vmcb->save.cr4        = cr4;
	vcpu->vmcb->control.clean  &= ~(1 << VMCB_CR);

	return 0;
}

static struct vmcb_seg *vmrun_seg(struct vmrun_vcpu *vcpu, int seg)
{
	struct vmcb_save_area *save = &vcpu->vmcb->save;

	switch (seg) {
		case VCPU_SREG_CS:   return &save->cs;
		case VCPU_SREG_DS:   return &save->ds;
		case VCPU_SREG_ES:   return &save->es;
		case VCPU_SREG_FS:   return &save->fs;
		case VCPU_SREG_GS:   return &save->gs;
		case VCPU_SREG_SS:   return &save->ss;
		case VCPU_SREG_TR:   return &save->tr;
		case VCPU_SREG_LDTR: return &save->ldtr;
	}

	BUG();

	return NULL;
}

static u64 vmrun_get_segment_base(struct vmrun_vcpu *vcpu, int seg)
{
	struct vmcb_seg *s = vmrun_seg(vcpu, seg);

	return s->base;
}

static void vmrun_get_segment(struct vmrun_vcpu *vcpu,
			      struct vmrun_segment *var, int seg)
{
	struct vmcb_seg *s = vmrun_seg(vcpu, seg);

	var->base     = s->base;
	var->limit    = s->limit;
	var->selector = s->selector;
	var->type     = s->attrib   & VMRUN_SELECTOR_TYPE_MASK;
	var->s        = (s->attrib >> VMRUN_SELECTOR_S_SHIFT)   & 1;
	var->dpl      = (s->attrib >> VMRUN_SELECTOR_DPL_SHIFT) & 3;
	var->present  = (s->attrib >> VMRUN_SELECTOR_P_SHIFT)   & 1;
	var->avl      = (s->attrib >> VMRUN_SELECTOR_AVL_SHIFT) & 1;
	var->l        = (s->attrib >> VMRUN_SELECTOR_L_SHIFT)   & 1;
	var->db       = (s->attrib >> VMRUN_SELECTOR_DB_SHIFT)  & 1;

	/*
	 * AMD CPUs circa 2014 track the G bit for all segments except CS.
	 * However, the SVM spec states that the G bit is not observed by the
	 * CPU, and some VMware virtual CPUs drop the G bit for all segments.
	 * So let's synthesize a legal G bit for all segments, this helps
	 * running VMRUN nested. It also helps cross-vendor migration, because
	 * Intel's vmentry has a check on the 'G' bit.
	 */
	var->g = s->limit > 0xfffff;

	/*
	 * AMD's VMCB does not have an explicit unusable field, so emulate it
	 * for cross vendor migration purposes by "not present"
	 */
	var->unusable = !var->present;

	switch (seg) {
		case VCPU_SREG_TR:
			/*
			 * Work around a bug where the busy flag in the tr selector
			 * isn't exposed
			 */
			var->type |= 0x2;
			break;

		case VCPU_SREG_DS:
		case VCPU_SREG_ES:
		case VCPU_SREG_FS:
		case VCPU_SREG_GS:
			/*
			 * The accessed bit must always be set in the segment
			 * descriptor cache, although it can be cleared in the
			 * descriptor, the cached bit always remains at 1. Since
			 * Intel has a check on this, set it here to support
			 * cross-vendor migration.
			 */
			if (!var->unusable)
				var->type |= 0x1;
			break;

		case VCPU_SREG_SS:
			/*
			 * On AMD CPUs sometimes the DB bit in the segment
			 * descriptor is left as 1, although the whole segment has
			 * been made unusable. Clear it here to pass an Intel VMX
			 * entry check when cross vendor migrating.
			 */
			if (var->unusable)
				var->db = 0;
			/* This is symmetric with svm_set_segment() */
			var->dpl = vcpu->vmcb->save.cpl;
			break;
	}
}

static void vmrun_set_segment(struct vmrun_vcpu *vcpu,
			      struct vmrun_segment *var, int seg)
{
	struct vmcb_seg *s = vmrun_seg(vcpu, seg);

	s->base     = var->base;
	s->limit    = var->limit;
	s->selector = var->selector;
	s->attrib   = (var->type & VMRUN_SELECTOR_TYPE_MASK);
	s->attrib  |= (var->s & 1) << VMRUN_SELECTOR_S_SHIFT;
	s->attrib  |= (var->dpl & 3) << VMRUN_SELECTOR_DPL_SHIFT;
	s->attrib  |= ((var->present & 1) && !var->unusable) << VMRUN_SELECTOR_P_SHIFT;
	s->attrib  |= (var->avl & 1) << VMRUN_SELECTOR_AVL_SHIFT;
	s->attrib  |= (var->l & 1) << VMRUN_SELECTOR_L_SHIFT;
	s->attrib  |= (var->db & 1) << VMRUN_SELECTOR_DB_SHIFT;
	s->attrib  |= (var->g & 1) << VMRUN_SELECTOR_G_SHIFT;

	/*
	 * This is always accurate, except if SYSRET returned to a segment
	 * with SS.DPL != 3.  Intel does not have this quirk, and always
	 * forces SS.DPL to 3 on sysret, so we ignore that case; fixing it
	 * would entail passing the CPL to userspace and back.
	 */
	if (seg == VCPU_SREG_SS)
		/* This is symmetric with svm_get_segment() */
		vcpu->vmcb->save.cpl = (var->dpl & 3);

	vcpu->vmcb->control.clean  &= ~(1 << VMCB_SEG);
}

static int vmrun_get_cpl(struct vmrun_vcpu *vcpu)
{
	return vcpu->vmcb->save.cpl;
}

static void vmrun_get_idt(struct vmrun_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size    = vcpu->vmcb->save.idtr.limit;
	dt->address = vcpu->vmcb->save.idtr.base;
}

static void vmrun_set_idt(struct vmrun_vcpu *vcpu, struct desc_ptr *dt)
{
	vcpu->vmcb->save.idtr.limit = dt->size;
	vcpu->vmcb->save.idtr.base  = dt->address ;
	vcpu->vmcb->control.clean  &= ~(1 << VMCB_DT);
}

static void vmrun_get_gdt(struct vmrun_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size    = vcpu->vmcb->save.gdtr.limit;
	dt->address = vcpu->vmcb->save.gdtr.base;
}

static void vmrun_set_gdt(struct vmrun_vcpu *vcpu, struct desc_ptr *dt)
{
	vcpu->vmcb->save.gdtr.limit = dt->size;
	vcpu->vmcb->save.gdtr.base  = dt->address ;
	vcpu->vmcb->control.clean  &= ~(1 << VMCB_DT);
}

static void vmrun_init_seg(struct vmcb_seg *seg)
{
	seg->selector = 0;
	seg->attrib = VMRUN_SELECTOR_P_MASK | VMRUN_SELECTOR_S_MASK |
		      VMRUN_SELECTOR_WRITE_MASK; /* Read/Write Data Segment */
	seg->limit = 0xffff;
	seg->base = 0;
}

static void vmrun_init_sys_seg(struct vmcb_seg *seg, uint32_t type)
{
	seg->selector = 0;
	seg->attrib = VMRUN_SELECTOR_P_MASK | type;
	seg->limit = 0xffff;
	seg->base = 0;
}

static void vmrun_vmcb_init(struct vmrun_vcpu *vcpu)
{
	struct vmcb_control_area *control = &vcpu->vmcb->control;
	struct vmcb_save_area    *save    = &vcpu->vmcb->save;

	unsigned long cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;

	control->intercept |= (1ULL << INTERCEPT_INTR);
	control->intercept |= (1ULL << INTERCEPT_NMI);
	control->intercept |= (1ULL << INTERCEPT_SMI);
	control->intercept |= (1ULL << INTERCEPT_VMRUN);
	control->intercept |= (1ULL << INTERCEPT_VMMCALL);
	control->clean     &= ~(1 << VMCB_INTERCEPTS);

	control->iopm_base_pa  = __sme_set(iopm_base);
	control->int_ctl       = V_INTR_MASK;

	vmrun_init_seg(&save->es);
	vmrun_init_seg(&save->ss);
	vmrun_init_seg(&save->ds);
	vmrun_init_seg(&save->fs);
	vmrun_init_seg(&save->gs);

	save->cs.selector = 0xf000;
	save->cs.base = 0xffff0000;
	/* Executable/Readable Code Segment */
	save->cs.attrib = VMRUN_SELECTOR_READ_MASK | VMRUN_SELECTOR_P_MASK |
			  VMRUN_SELECTOR_S_MASK | VMRUN_SELECTOR_CODE_MASK;
	save->cs.limit = 0xffff;

	save->gdtr.limit = 0xffff;
	save->idtr.limit = 0xffff;

	vmrun_init_sys_seg(&save->ldtr, SEG_TYPE_LDT);
	vmrun_init_sys_seg(&save->tr, SEG_TYPE_AVAIL_TSS16);

	save->efer = EFER_SVME;
	save->cr0 = cr0 | X86_CR0_PE | X86_CR0_PG | X86_CR0_WP;
	save->cr4 = X86_CR4_PAE;
	save->rip = 0x0000fff0;
	save->dr6 = 0xffff0ff0;
	save->rflags = 2;
	control->clean &= ~(1 << VMCB_CR);
	control->clean = 0;

	vcpu->cr0 = cr0;
	vcpu->efer = 0;
	vcpu->hflags |= HF_GIF_MASK;
	vcpu->asid_generation = 0;
	vcpu->regs[VCPU_REGS_RIP] = save->rip;

	vmrun_mmu_reset_context(vcpu);
	
	// vmrun_make_request(VMRUN_REQ_EVENT, vcpu); // Needed?
}

static void vmrun_vcpu_setup_old(struct vmrun_vcpu *vcpu)
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

static void vmrun_new_asid(struct vmrun_vcpu *vcpu, struct vmrun_cpu_data *cd)
{
	if (cd->next_asid > cd->max_asid) {
		++cd->asid_generation;
		cd->next_asid = 1;
		vcpu->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	}

	vcpu->asid_generation = cd->asid_generation;
	vcpu->vmcb->control.asid = cd->next_asid++;

	vcpu->vmcb->control.clean &= ~(1 << VMCB_ASID);
}

static void vmrun_vcpu_run(struct vmrun_vcpu *vcpu)
{
	int cpu = raw_smp_processor_id();
	u64 cr8;

	vcpu->vmcb->save.rax = vcpu->regs[VCPU_REGS_RAX];
	vcpu->vmcb->save.rsp = vcpu->regs[VCPU_REGS_RSP];
	vcpu->vmcb->save.rip = vcpu->regs[VCPU_REGS_RIP];

	struct vmrun_cpu_data *cd = per_cpu(local_cpu_data, cpu);

	/* FIXME: handle wraparound of asid_generation */
	if (vcpu->asid_generation != cd->asid_generation)
		vmrun_new_asid(vcpu, cd);

	cr8 = vcpu->cr8;
	vcpu->vmcb->control.int_ctl &= ~V_TPR_MASK;
	vcpu->vmcb->control.int_ctl |= cr8 & V_TPR_MASK;

	vcpu->vmcb->save.cr2 = vcpu->cr2;

	asm volatile (SVM_CLGI);

	local_irq_enable();

	asm volatile (
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
		SVM_VMLOAD "\n\t"
		SVM_VMRUN "\n\t"
		SVM_VMSAVE "\n\t"
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
		:
		: [vcpu]"a"(vcpu),
		  [vmcb]"i"(offsetof(struct vcpu_svm, vmcb_pa)),
		  [rbx] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_RBX])),
		  [rcx] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_RCX])),
		  [rdx] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_RDX])),
		  [rsi] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_RSI])),
		  [rdi] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_RDI])),
		  [rbp] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_RBP])),
		  [r8]  "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R8])),
		  [r9]  "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R9])),
		  [r10] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R10])),
		  [r11] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R11])),
		  [r12] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R12])),
		  [r13] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R13])),
		  [r14] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R14])),
		  [r15] "i"(offsetof(struct vcpu_svm, vcpu->regs[VCPU_REGS_R15]))
		: "cc", "memory",
		  "rbx", "rcx", "rdx", "rsi", "rdi",
		  "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15");
	
	wrmsrl(MSR_GS_BASE, vcpu->host.gs_base);

	cd->tss_desc->type = 9; /* available 32/64-bit TSS */
	load_TR_desc();

	local_irq_disable();

	vcpu->cr2 = vcpu->vmcb->save.cr2;
	vcpu->regs[VCPU_REGS_RAX] = vcpu->vmcb->save.rax;
	vcpu->regs[VCPU_REGS_RSP] = vcpu->vmcb->save.rsp;
	vcpu->regs[VCPU_REGS_RIP] = vcpu->vmcb->save.rip;

	if (unlikely(vcpu->vmcb->control.exit_code == SVM_EXIT_NMI))
		__this_cpu_write(local_vcpu, vcpu);

	asm volatile (SVM_STGI);

	/* Any pending NMI will happen here */

	if (unlikely(vcpu->vmcb->control.exit_code == SVM_EXIT_NMI))
		__this_cpu_write(local_vcpu, NULL);

	if (!vmrun_is_cr_intercept(vcpu, INTERCEPT_CR8_WRITE)) {
		vcpu->cr8 = vcpu->vmcb->control.int_ctl & V_TPR_MASK;
	}

	vcpu->next_rip = 0;

	vcpu->vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;

//	if (npt_enabled) {
//		vcpu->regs_avail &= ~(1 << VCPU_EXREG_PDPTR);
//		vcpu->regs_dirty &= ~(1 << VCPU_EXREG_PDPTR);
//	}

	vcpu->vmcb->control.clean = ((1 << VMCB_DIRTY_MAX) - 1) & ~VMCB_ALWAYS_DIRTY_MASK;
}
// STACK_FRAME_NON_STANDARD(vmrun_vcpu_run);

static int intr_interception(struct vmrun_vcpu *vcpu)
{
	// ++svm->vcpu.stat.irq_exits;
	return 1;
}

static int nmi_interception(struct vmrun_vcpu *vcpu)
{
	return 1;
}

static int cpuid_interception(struct vmrun_vcpu *vcpu)
{
	vcpu->next_rip = vmrun_rip_read(vcpu) + 2;
	//return kvm_emulate_cpuid(vcpu);
	return 0;
}

static int vmmcall_interception(struct vmrun_vcpu *vcpu)
{
	vcpu->next_rip = vmrun_rip_read(vcpu) + 3;
	//return kvm_emulate_hypercall(vcpu);
	return 0;
}

static int (*const vmrun_exit_handlers[])(struct vmrun_vcpu *vcpu) = {
	[SVM_EXIT_INTR]				= intr_interception,
	[SVM_EXIT_NMI]				= nmi_interception,
	[SVM_EXIT_CPUID]			= cpuid_interception,
	[SVM_EXIT_VMMCALL]			= vmmcall_interception,
};

static void vmrun_vcpu_dump_vmcb(struct vmrun_vcpu *vcpu)
{
	struct vmcb_control_area *control = &vcpu->vmcb->control;
	struct vmcb_save_area *save = &vcpu->vmcb->save;

	pr_err("VMCB Control Area:\n");
	pr_err("%-20s%04x\n", "cr_read:", control->intercept_cr & 0xffff);
	pr_err("%-20s%04x\n", "cr_write:", control->intercept_cr >> 16);
	pr_err("%-20s%04x\n", "dr_read:", control->intercept_dr & 0xffff);
	pr_err("%-20s%04x\n", "dr_write:", control->intercept_dr >> 16);
	pr_err("%-20s%08x\n", "exceptions:", control->intercept_exceptions);
	pr_err("%-20s%016llx\n", "intercepts:", control->intercept);
	pr_err("%-20s%d\n", "pause filter count:", control->pause_filter_count);
	pr_err("%-20s%016llx\n", "iopm_base_pa:", control->iopm_base_pa);
	pr_err("%-20s%016llx\n", "msrpm_base_pa:", control->msrpm_base_pa);
	pr_err("%-20s%016llx\n", "tsc_offset:", control->tsc_offset);
	pr_err("%-20s%d\n", "asid:", control->asid);
	pr_err("%-20s%d\n", "tlb_ctl:", control->tlb_ctl);
	pr_err("%-20s%08x\n", "int_ctl:", control->int_ctl);
	pr_err("%-20s%08x\n", "int_vector:", control->int_vector);
	pr_err("%-20s%08x\n", "int_state:", control->int_state);
	pr_err("%-20s%08x\n", "exit_code:", control->exit_code);
	pr_err("%-20s%016llx\n", "exit_info1:", control->exit_info_1);
	pr_err("%-20s%016llx\n", "exit_info2:", control->exit_info_2);
	pr_err("%-20s%08x\n", "exit_int_info:", control->exit_int_info);
	pr_err("%-20s%08x\n", "exit_int_info_err:", control->exit_int_info_err);
	pr_err("%-20s%lld\n", "nested_ctl:", control->nested_ctl);
	pr_err("%-20s%016llx\n", "nested_cr3:", control->nested_cr3);
	pr_err("%-20s%016llx\n", "avic_vapic_bar:", control->avic_vapic_bar);
	pr_err("%-20s%08x\n", "event_inj:", control->event_inj);
	pr_err("%-20s%08x\n", "event_inj_err:", control->event_inj_err);
	pr_err("%-20s%lld\n", "virt_ext:", control->virt_ext);
	pr_err("%-20s%016llx\n", "next_rip:", control->next_rip);
	pr_err("%-20s%016llx\n", "avic_backing_page:", control->avic_backing_page);
	pr_err("%-20s%016llx\n", "avic_logical_id:", control->avic_logical_id);
	pr_err("%-20s%016llx\n", "avic_physical_id:", control->avic_physical_id);

	pr_err("VMCB State Save Area:\n");
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "es:",
	       save->es.selector, save->es.attrib,
	       save->es.limit, save->es.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "cs:",
	       save->cs.selector, save->cs.attrib,
	       save->cs.limit, save->cs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "ss:",
	       save->ss.selector, save->ss.attrib,
	       save->ss.limit, save->ss.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "ds:",
	       save->ds.selector, save->ds.attrib,
	       save->ds.limit, save->ds.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "fs:",
	       save->fs.selector, save->fs.attrib,
	       save->fs.limit, save->fs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "gs:",
	       save->gs.selector, save->gs.attrib,
	       save->gs.limit, save->gs.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "gdtr:",
	       save->gdtr.selector, save->gdtr.attrib,
	       save->gdtr.limit, save->gdtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "ldtr:",
	       save->ldtr.selector, save->ldtr.attrib,
	       save->ldtr.limit, save->ldtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "idtr:",
	       save->idtr.selector, save->idtr.attrib,
	       save->idtr.limit, save->idtr.base);
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n",
	       "tr:",
	       save->tr.selector, save->tr.attrib,
	       save->tr.limit, save->tr.base);
	pr_err("cpl:            %d                efer:         %016llx\n",
	       save->cpl, save->efer);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "cr0:", save->cr0, "cr2:", save->cr2);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "cr3:", save->cr3, "cr4:", save->cr4);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "dr6:", save->dr6, "dr7:", save->dr7);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "rip:", save->rip, "rflags:", save->rflags);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "rsp:", save->rsp, "rax:", save->rax);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "star:", save->star, "lstar:", save->lstar);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "cstar:", save->cstar, "sfmask:", save->sfmask);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "kernel_gs_base:", save->kernel_gs_base,
	       "sysenter_cs:", save->sysenter_cs);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "sysenter_esp:", save->sysenter_esp,
	       "sysenter_eip:", save->sysenter_eip);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "gpat:", save->g_pat, "dbgctl:", save->dbgctl);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "br_from:", save->br_from, "br_to:", save->br_to);
	pr_err("%-15s %016llx %-13s %016llx\n",
	       "excp_from:", save->last_excp_from,
	       "excp_to:", save->last_excp_to);
}

static int vmrun_is_external_interrupt(u32 info)
{
	info &= SVM_EVTINJ_TYPE_MASK | SVM_EVTINJ_VALID;

	return info == (SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_INTR);
}

static void vmrun_get_exit_info(struct vmrun_vcpu *vcpu, u64 *info1, u64 *info2)
{
	struct vmcb_control_area *control = &vcpu->vmcb->control;

	*info1 = control->exit_info_1;
	*info2 = control->exit_info_2;
}

static int vmrun_vcpu_handle_exit(struct vmrun_vcpu *vcpu)
{
	struct vmrun_run *vmrun_run = vcpu->run;
	u32 exit_code = vcpu->vmcb->control.exit_code;

	if (!vmrun_is_cr_intercept(vcpu, INTERCEPT_CR0_WRITE))
		vcpu->cr0 = vcpu->vmcb->save.cr0;
	
	if (npt_enabled)
		vcpu->cr3 = vcpu->vmcb->save.cr3;

	// svm_complete_interrupts(svm);

	if (vcpu->vmcb->control.exit_code == SVM_EXIT_ERR) {
		vmrun_run->exit_reason = VMRUN_EXIT_FAIL_ENTRY;
		vmrun_run->fail_entry.hardware_entry_failure_reason
			= vcpu->vmcb->control.exit_code;

		pr_err("VMRUN: FAILED VMRUN WITH VMCB:\n");
		vmrun_vcpu_dump_vmcb(vcpu);
		return 0;
	}

	if (vmrun_is_external_interrupt(vcpu->vmcb->control.exit_int_info) &&
	    exit_code != SVM_EXIT_EXCP_BASE + PF_VECTOR &&
	    exit_code != SVM_EXIT_NPF && exit_code != SVM_EXIT_TASK_SWITCH &&
	    exit_code != SVM_EXIT_INTR && exit_code != SVM_EXIT_NMI)
		printk(KERN_ERR "%s: unexpected exit_int_info 0x%x "
			       "exit_code 0x%x\n",
		       __func__, vcpu->vmcb->control.exit_int_info,
		       exit_code);

	if (exit_code >= ARRAY_SIZE(vmrun_exit_handlers) || !vmrun_exit_handlers[exit_code]) {
		WARN_ONCE(1, "vmrun_vcpu_handle_exit: unexpected exit reason 0x%x\n", exit_code);
		// vmrun_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	return vmrun_exit_handlers[exit_code](vcpu);
}

static inline struct vmrun_vcpu *vmrun_get_vcpu(struct vmrun *vmrun, int i)
{
	/* Pairs with smp_wmb() in vmrun_vm_ioctl_create_vcpu, in case
	 * the caller has read vmrun->online_vcpus before (as is the case
	 * for vmrun_for_each_vcpu, for example).
	 */
	smp_rmb();

	return vmrun->vcpus[i];
}

#define vmrun_for_each_vcpu(idx, vcpup, vmrun) \
	for (idx = 0; \
	     idx < atomic_read(&vmrun->online_vcpus) && \
	     (vcpup = vmrun_get_vcpu(vmrun, idx)) != NULL; \
	     idx++)

static inline struct vmrun_vcpu *vmrun_get_vcpu_by_id(struct vmrun *vmrun, int id)
{
	struct vmrun_vcpu *vcpu = NULL;
	int i;

	if (id < 0)
		return NULL;
	
	if (id < VMRUN_MAX_VCPUS)
		vcpu = vmrun_get_vcpu(vmrun, id);
	
	if (vcpu && vcpu->vcpu_id == id)
		return vcpu;
	
	vmrun_for_each_vcpu(i, vcpu, vmrun)
		if (vcpu->vcpu_id == id)
			return vcpu;
	
	return NULL;
}

static void vmrun_svm_vcpu_load(struct vmrun_vcpu *vcpu, int cpu)
{
	if (unlikely(cpu != vcpu->cpu)) {
		vcpu->asid_generation     = 0;
		vcpu->vmcb->control.clean = 0;
	}

	rdmsrl(MSR_GS_BASE, vcpu->host.gs_base);
	savesegment(fs, vcpu->host.fs);
	savesegment(gs, vcpu->host.gs);
	vcpu->host.ldt = vmrun_read_ldt();
}

int vmrun_vcpu_load(struct vmrun_vcpu *vcpu)
{
	int cpu;

	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;

	cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);
	vmrun_svm_vcpu_load(vcpu, cpu);
	put_cpu();

	return 0;
}

static void vmrun_svm_vcpu_put(struct vmrun_vcpu *vcpu)
{
	vmrun_load_ldt(vcpu->host.ldt);
	loadsegment(fs, vcpu->host.fs);
	wrmsrl(MSR_KERNEL_GS_BASE, current->thread.gsbase);
	load_gs_index(vcpu->host.gs);
}

void vmrun_vcpu_put(struct vmrun_vcpu *vcpu)
{
	preempt_disable();
	vmrun_svm_vcpu_put(vcpu);
	preempt_notifier_unregister(&vcpu->preempt_notifier);
	preempt_enable();

	mutex_unlock(&vcpu->mutex);
}

//bool vmrun_vcpu_wake_up(struct vmrun_vcpu *vcpu)
//{
//	struct swait_queue_head *wqp;
//
//	wqp = vmrun_arch_vcpu_wq(vcpu);
//
//	if (swq_has_sleeper(wqp)) {
//		swake_up(wqp);
//		++vcpu->stat.halt_wakeup;
//		return true;
//	}
//
//	return false;
//}

int vmrun_vcpu_init(struct vmrun_vcpu *vcpu, struct vmrun *vmrun, unsigned id)
{
	struct page *run_page;
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->vmrun = vmrun;
	vcpu->vcpu_id = id;
	vcpu->pid = NULL;

	vcpu->pre_pcpu = -1;
	INIT_LIST_HEAD(&vcpu->blocked_vcpu_list);

	run_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (!run_page) {
		r = -ENOMEM;
		goto fail;
	}

	vcpu->run = page_address(run_page);

	vcpu->spin_loop.in_spin_loop = false;
	vcpu->spin_loop.dy_eligible  = false;
	vcpu->preempted = false;

	r = vmrun_mmu_create(vcpu);

	if (r < 0)
		goto fail_free_run_page;

	// vcpu->pending_external_vector = -1;
	// vcpu->preempted_in_kernel = false;

	return 0;

fail_free_run_page:
	free_page((unsigned long)vcpu->run);
fail:
	return r;
}

void vmrun_vcpu_uninit(struct vmrun_vcpu *vcpu)
{
	int idx;

	/*
	 * no need for rcu_read_lock as VCPU_RUN is the only place that
	 * will change the vcpu->pid pointer and on uninit all file
	 * descriptors are already gone.
	 */
	put_pid(rcu_dereference_protected(vcpu->pid, 1));

	idx = srcu_read_lock(&vcpu->vmrun->srcu);
	vmrun_mmu_destroy(vcpu);
	srcu_read_unlock(&vcpu->vmrun->srcu, idx);

	free_page((unsigned long)vcpu->run);
}

static void vmrun_vcpu_free(struct vmrun_vcpu *vcpu)
{
	__free_page(pfn_to_page(__sme_clr(vcpu->vmcb_pa) >> PAGE_SHIFT));
	vmrun_vcpu_uninit(vcpu);
	kmem_cache_free(vmrun_vcpu_cache, vcpu);
}

static struct vmrun_vcpu *vmrun_vcpu_create(struct vmrun *vmrun, unsigned int id)
{
	struct vmrun_vcpu *vcpu;
	struct page *vmcb_page;
	struct page *hsave_page;
	int err;

	vcpu->vmrun = vmrun;

	vcpu = kmem_cache_zalloc(vmrun_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = vmrun_vcpu_init(vcpu, vmrun, id);
	if (err)
		goto free_vcpu;

	err = -ENOMEM;
	vmcb_page = alloc_page(GFP_KERNEL);
	if (!vmcb_page)
		goto uninit_vcpu;

	hsave_page = alloc_page(GFP_KERNEL);
	if (!hsave_page)
		goto free_vmcb_page;

	vcpu->vmcb = page_address(vmcb_page);
	clear_page(vcpu->vmcb);
	vcpu->vmcb_pa = __sme_set(page_to_pfn(vmcb_page) << PAGE_SHIFT);
	vcpu->asid_generation = 0;
	vmrun_vmcb_init(vcpu);

//	vcpu->cpu_data = per_cpu(cpu_data, me);
//	per_cpu(local_vcpu, me) = vcpu;
//	per_cpu(local_vmcb, me) = vcpu->vmcb;

	printk("vcpu_create: Created vcpu\n");

	return vcpu;

free_vmcb_page:
	__free_page(vmcb_page);
uninit_vcpu:
	vmrun_vcpu_uninit(vcpu);
free_vcpu:
	kmem_cache_free(vmrun_vcpu_cache, vcpu);
out:
	return ERR_PTR(err);
}

static void vmrun_vcpu_unload_mmu(struct vmrun_vcpu *vcpu)
{
	int r;
	r = vmrun_vcpu_load(vcpu);
	BUG_ON(r);
	vmrun_mmu_unload(vcpu);
	vmrun_vcpu_put(vcpu);
}

static void vmrun_free_vcpus(struct vmrun *vmrun)
{
	unsigned int i;
	struct vmrun_vcpu *vcpu;

	/*
	 * Unpin any mmu pages first.
	 */
	vmrun_for_each_vcpu(i, vcpu, vmrun) {
		//vmrun_clear_async_pf_completion_queue(vcpu);
		vmrun_vcpu_unload_mmu(vcpu);
	}
	
	vmrun_for_each_vcpu(i, vcpu, vmrun)
		vmrun_vcpu_free(vcpu);

	mutex_lock(&vmrun->lock);
	
	for (i = 0; i < atomic_read(&vmrun->online_vcpus); i++)
		vmrun->vcpus[i] = NULL;

	atomic_set(&vmrun->online_vcpus, 0);
	
	mutex_unlock(&vmrun->lock);
}

void vmrun_vcpu_reset(struct vmrun_vcpu *vcpu, bool init_event)
{
	vcpu->hflags = 0;
	vcpu->cr2    = 0;

	//vmrun_make_request(VMRUN_REQ_EVENT, vcpu);

	memset(vcpu->regs, 0, sizeof(vcpu->regs));
	vcpu->regs_avail = ~0;
	vcpu->regs_dirty = ~0;

	vmrun_vmcb_init(vcpu);

	// u32 dummy;
	// u32 eax = 1;
	// vmrun_cpuid(vcpu, &eax, &dummy, &dummy, &dummy, true);
	// vmrun_register_write(vcpu, VCPU_REGS_RDX, eax);
}

int vmrun_vcpu_setup(struct vmrun_vcpu *vcpu)
{
	int r;

	r = vmrun_vcpu_load(vcpu);

	if (r)
		return r;

	vmrun_vcpu_reset(vcpu, false);

	vmrun_mmu_setup(vcpu);

	vmrun_vcpu_put(vcpu);

	return r;
}

void vmrun_vcpu_destroy(struct vmrun_vcpu *vcpu)
{
	int r;

	//vcpu->arch.apf.msr_val = 0;

	r = vmrun_vcpu_load(vcpu);

	BUG_ON(r);

	vmrun_mmu_unload(vcpu);

	vmrun_vcpu_put(vcpu);

	vmrun_vcpu_free(vcpu);
}

/*
 * Returns 1 to let vcpu_run() continue the guest execution loop without
 * exiting to the userspace.  Otherwise, the value will be returned to the
 * userspace.
 */
static int vmrun_vcpu_enter_guest(struct vmrun_vcpu *vcpu)
{
	int r;
	
	r = vmrun_mmu_reload(vcpu);
	
	if (unlikely(r)) {
		goto out;
	}

	preempt_disable();
	
	// vmrun_load_guest_fpu(vcpu);

	/*
	 * Disable IRQs before setting IN_GUEST_MODE.  Posted interrupt
	 * IPI are then delayed after guest entry, which ensures that they
	 * result in virtual interrupt delivery.
	 */
	local_irq_disable();
	
	vcpu->mode = IN_GUEST_MODE;

	srcu_read_unlock(&vcpu->vmrun->srcu, vcpu->srcu_idx);

	/*
	 * 1) We should set ->mode before checking ->requests.  Please see
	 * the comment in vmrun_vcpu_exiting_guest_mode().
	 *
	 * 2) For APICv, we should set ->mode before checking PIR.ON.  This
	 * pairs with the memory barrier implicit in pi_test_and_set_on
	 * (see vmx_deliver_posted_interrupt).
	 *
	 * 3) This also orders the write to mode from any reads to the page
	 * tables done while the VCPU is running.  Please see the comment
	 * in vmrun_flush_remote_tlbs.
	 */
	smp_mb__after_srcu_read_unlock();

	// vmrun_load_guest_xcr0(vcpu);
	
	guest_enter_irqoff();

	vmrun_vcpu_run(vcpu);

	vcpu->mode = OUTSIDE_GUEST_MODE;
	
	smp_wmb();

	// vmrun_put_guest_xcr0(vcpu);

//      Handle external interrupts
//	local_irq_enable();
//	/*
//	 * We must have an instruction with interrupts enabled, so
//	 * the timer interrupt isn't delayed by the interrupt shadow.
//	 */
//	asm("nop");
//	local_irq_disable();

	guest_exit_irqoff();

	local_irq_enable();
	
	preempt_enable();

	vcpu->srcu_idx = srcu_read_lock(&vcpu->vmrun->srcu);

	// vcpu->gpa_available = false;
	
	r = vmrun_vcpu_handle_exit(vcpu);
	
out:
	return r;
}

static inline int vmrun_vcpu_block(struct vmrun *vmrun, struct vmrun_vcpu *vcpu)
{
	if (vcpu->mp_state != VMRUN_MP_STATE_RUNNABLE)
	{
		srcu_read_unlock(&vmrun->srcu, vcpu->srcu_idx);
		
		// vmrun_vcpu_block(vcpu);
		
		vcpu->srcu_idx = srcu_read_lock(&vmrun->srcu);

//		if (!vmrun_check_request(VMRUN_REQ_UNHALT, vcpu))
//			return 1;
	}
	
	switch(vcpu->mp_state) {
		case VMRUN_MP_STATE_HALTED:
			vcpu->mp_state = VMRUN_MP_STATE_RUNNABLE;
		case VMRUN_MP_STATE_RUNNABLE:
			break;
		case VMRUN_MP_STATE_INIT_RECEIVED:
			break;
		default:
			return -EINTR;
			break;
	}
	
	return 1;
}

static int vmrun_vcpu_run(struct vmrun_vcpu *vcpu)
{
	int r;
	struct vmrun *vmrun = vcpu->vmrun;

	vcpu->srcu_idx = srcu_read_lock(&vmrun->srcu);

	for (;;) {
		if (vcpu->mp_state == VMRUN_MP_STATE_RUNNABLE) {
			r = vmrun_vcpu_enter_guest(vcpu);
		} else {
			r = -EINVAL;
			// r = vmrun_vcpu_block(vmrun, vcpu);
		}

		if (r <= 0)
			break;

//		if (signal_pending(current)) {
//			r = -EINTR;
//			vcpu->run->exit_reason = VMRUN_EXIT_INTR;
//			++vcpu->stat.signal_exits;
//			break;
//		}
		
		if (need_resched()) {
			srcu_read_unlock(&vmrun->srcu, vcpu->srcu_idx);
			cond_resched();
			vcpu->srcu_idx = srcu_read_lock(&vmrun->srcu);
		}
	}

	srcu_read_unlock(&vmrun->srcu, vcpu->srcu_idx);

	return r;
}

int vmrun_vcpu_ioctl_run(struct vmrun_vcpu *vcpu, struct vmrun_run *vmrun_run)
{
	int r;

//	if (vcpu->sigset_active)
//		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (vmrun_run->immediate_exit)
		r = -EINTR;
	else
		r = vmrun_vcpu_run(vcpu);

out:
	// vmrun_post_vmrun_run_save(vcpu);

	return r;
}

int vmrun_vcpu_ioctl_get_regs(struct vmrun_vcpu *vcpu, struct vmrun_regs *regs)
{
	regs->rax = vmrun_register_read(vcpu, VCPU_REGS_RAX);
	regs->rbx = vmrun_register_read(vcpu, VCPU_REGS_RBX);
	regs->rcx = vmrun_register_read(vcpu, VCPU_REGS_RCX);
	regs->rdx = vmrun_register_read(vcpu, VCPU_REGS_RDX);
	regs->rsi = vmrun_register_read(vcpu, VCPU_REGS_RSI);
	regs->rdi = vmrun_register_read(vcpu, VCPU_REGS_RDI);
	regs->rsp = vmrun_register_read(vcpu, VCPU_REGS_RSP);
	regs->rbp = vmrun_register_read(vcpu, VCPU_REGS_RBP);
	regs->r8  = vmrun_register_read(vcpu, VCPU_REGS_R8);
	regs->r9  = vmrun_register_read(vcpu, VCPU_REGS_R9);
	regs->r10 = vmrun_register_read(vcpu, VCPU_REGS_R10);
	regs->r11 = vmrun_register_read(vcpu, VCPU_REGS_R11);
	regs->r12 = vmrun_register_read(vcpu, VCPU_REGS_R12);
	regs->r13 = vmrun_register_read(vcpu, VCPU_REGS_R13);
	regs->r14 = vmrun_register_read(vcpu, VCPU_REGS_R14);
	regs->r15 = vmrun_register_read(vcpu, VCPU_REGS_R15);
	regs->rip = vmrun_register_read(vcpu, VCPU_REGS_RIP);
	regs->rflags = vcpu->vmcb->save.rflags;

	return 0;
}

int vmrun_vcpu_ioctl_set_regs(struct vmrun_vcpu *vcpu, struct vmrun_regs *regs)
{
	vmrun_register_write(vcpu, VCPU_REGS_RAX, regs->rax);
	vmrun_register_write(vcpu, VCPU_REGS_RBX, regs->rbx);
	vmrun_register_write(vcpu, VCPU_REGS_RCX, regs->rcx);
	vmrun_register_write(vcpu, VCPU_REGS_RDX, regs->rdx);
	vmrun_register_write(vcpu, VCPU_REGS_RSI, regs->rsi);
	vmrun_register_write(vcpu, VCPU_REGS_RDI, regs->rdi);
	vmrun_register_write(vcpu, VCPU_REGS_RSP, regs->rsp);
	vmrun_register_write(vcpu, VCPU_REGS_RBP, regs->rbp);
	vmrun_register_write(vcpu, VCPU_REGS_R8,  regs->r8);
	vmrun_register_write(vcpu, VCPU_REGS_R9,  regs->r9);
	vmrun_register_write(vcpu, VCPU_REGS_R10, regs->r10);
	vmrun_register_write(vcpu, VCPU_REGS_R11, regs->r11);
	vmrun_register_write(vcpu, VCPU_REGS_R12, regs->r12);
	vmrun_register_write(vcpu, VCPU_REGS_R13, regs->r13);
	vmrun_register_write(vcpu, VCPU_REGS_R14, regs->r14);
	vmrun_register_write(vcpu, VCPU_REGS_R15, regs->r15);
	vmrun_register_write(vcpu, VCPU_REGS_RIP, regs->rip);
	vcpu->vmcb->save.rflags = regs->rflags;

	// vcpu->exception.pending = false;
	
	// vmrun_make_request(VMRUN_REQ_EVENT, vcpu);

	return 0;
}

void vmrun_get_cs_db_l_bits(struct vmrun_vcpu *vcpu, int *db, int *l)
{
	struct vmrun_segment cs;

	vmrun_get_segment(vcpu, &cs, VCPU_SREG_CS);
	*db = cs.db;
	*l = cs.l;
}

int vmrun_vcpu_ioctl_get_sregs(struct vmrun_vcpu *vcpu,
			       struct vmrun_sregs *sregs)
{
	struct desc_ptr dt;

	vmrun_get_segment(vcpu, &sregs->cs,  VCPU_SREG_CS);
	vmrun_get_segment(vcpu, &sregs->ds,  VCPU_SREG_DS);
	vmrun_get_segment(vcpu, &sregs->es,  VCPU_SREG_ES);
	vmrun_get_segment(vcpu, &sregs->fs,  VCPU_SREG_FS);
	vmrun_get_segment(vcpu, &sregs->gs,  VCPU_SREG_GS);
	vmrun_get_segment(vcpu, &sregs->ss,  VCPU_SREG_SS);
	vmrun_get_segment(vcpu, &sregs->tr,  VCPU_SREG_TR);
	vmrun_get_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	vmrun_get_idt(vcpu, &dt);
	sregs->idt.limit = dt.size;
	sregs->idt.base = dt.address;

	vmrun_get_gdt(vcpu, &dt);
	sregs->gdt.limit = dt.size;
	sregs->gdt.base = dt.address;

	sregs->cr0  = vmrun_read_cr0(vcpu);
	sregs->cr2  = vcpu->cr2;
	sregs->cr3  = vmrun_read_cr3(vcpu);
	sregs->cr4  = vmrun_read_cr4(vcpu);
	sregs->cr8  = vcpu->cr8;
	sregs->efer = vcpu->efer;

	return 0;
}

static void vmrun_set_efer(struct vmrun_vcpu *vcpu, u64 efer)
{
	vcpu->efer = efer;
	if (!npt_enabled && !(efer & EFER_LMA))
		efer &= ~EFER_LME;

	vcpu->vmcb->save.efer      = efer | EFER_SVME;
	vcpu->vmcb->control.clean &= ~(1 << VMCB_CR);
}

int vmrun_vcpu_ioctl_set_sregs(struct vmrun_vcpu *vcpu,
			       struct vmrun_sregs *sregs)
{
	int mmu_reset_needed = 0;
	int pending_vec, max_bits, idx;
	struct desc_ptr dt;

	dt.size = sregs->idt.limit;
	dt.address = sregs->idt.base;
	vmrun_set_idt(vcpu, &dt);
	
	dt.size = sregs->gdt.limit;
	dt.address = sregs->gdt.base;
	vmrun_set_gdt(vcpu, &dt);

	vcpu->cr2 = sregs->cr2;
	mmu_reset_needed |= vmrun_read_cr3(vcpu) != sregs->cr3;
	vcpu->cr3 = sregs->cr3;
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->regs_avail);

	vcpu->cr8 = sregs->cr8;

	mmu_reset_needed |= vcpu->efer != sregs->efer;
	vmrun_set_efer(vcpu, sregs->efer);

	mmu_reset_needed |= vmrun_read_cr0(vcpu) != sregs->cr0;
	vmrun_set_cr0(vcpu, sregs->cr0);
	vcpu->cr0 = sregs->cr0;

	mmu_reset_needed |= vmrun_read_cr4(vcpu) != sregs->cr4;
	vmrun_set_cr4(vcpu, sregs->cr4);

	if (mmu_reset_needed)
		vmrun_mmu_reset_context(vcpu);

	vmrun_set_segment(vcpu, &sregs->cs,  VCPU_SREG_CS);
	vmrun_set_segment(vcpu, &sregs->ds,  VCPU_SREG_DS);
	vmrun_set_segment(vcpu, &sregs->es,  VCPU_SREG_ES);
	vmrun_set_segment(vcpu, &sregs->fs,  VCPU_SREG_FS);
	vmrun_set_segment(vcpu, &sregs->gs,  VCPU_SREG_GS);
	vmrun_set_segment(vcpu, &sregs->ss,  VCPU_SREG_SS);
	vmrun_set_segment(vcpu, &sregs->tr,  VCPU_SREG_TR);
	vmrun_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	vmrun_clr_cr_intercept(vcpu, INTERCEPT_CR8_WRITE);

	// vmrun_make_request(VMRUN_REQ_EVENT, vcpu);

	return 0;
}

static long vmrun_vcpu_ioctl(struct file *filp,
			     unsigned int ioctl,
			     unsigned long arg)
{
	struct vmrun_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;
	struct vmrun_sregs *vmrun_sregs = NULL;

	if (vcpu->vmrun->mm != current->mm)
		return -EIO;

	if (unlikely(_IOC_TYPE(ioctl) != VMRUNIO))
		return -EINVAL;

	r = vmrun_vcpu_load(vcpu);
	
	if (r)
		return r;
	
	switch (ioctl) {
		case VMRUN_RUN: {
			struct pid *oldpid;
			r = -EINVAL;

			if (arg)
				goto out;

			oldpid = rcu_access_pointer(vcpu->pid);

			if (unlikely(oldpid != current->pids[PIDTYPE_PID].pid)) {
				/* The thread running this VCPU changed. */
				struct pid *newpid = get_task_pid(current, PIDTYPE_PID);

				rcu_assign_pointer(vcpu->pid, newpid);

				if (oldpid)
					synchronize_rcu();

				put_pid(oldpid);
			}

			r = vmrun_vcpu_ioctl_run(vcpu, vcpu->run);
			break;
		}

		case VMRUN_GET_REGS: {
			struct vmrun_regs *vmrun_regs;
			r = -ENOMEM;

			vmrun_regs = kzalloc(sizeof(struct vmrun_regs), GFP_KERNEL);

			if (!vmrun_regs)
				goto out;

			r = vmrun_vcpu_ioctl_get_regs(vcpu, vmrun_regs);

			if (r)
				goto out_free;
			r = -EFAULT;

			if (copy_to_user(argp, vmrun_regs, sizeof(struct vmrun_regs)))
				goto out_free;

			r = 0;

		out_free:
			kfree(vmrun_regs);
			break;
		}

		case VMRUN_SET_REGS: {
			struct vmrun_regs *vmrun_regs;
			r = -ENOMEM;

			vmrun_regs = memdup_user(argp, sizeof(*vmrun_regs));

			if (IS_ERR(vmrun_regs)) {
				r = PTR_ERR(vmrun_regs);
				goto out;
			}

			r = vmrun_vcpu_ioctl_set_regs(vcpu, vmrun_regs);
			kfree(vmrun_regs);
			break;
		}

		case VMRUN_GET_SREGS: {
			vmrun_sregs = kzalloc(sizeof(struct vmrun_sregs), GFP_KERNEL);
			r = -ENOMEM;

			if (!vmrun_sregs)
				goto out;

			r = vmrun_vcpu_ioctl_get_sregs(vcpu, vmrun_sregs);

			if (r)
				goto out;

			r = -EFAULT;

			if (copy_to_user(argp, vmrun_sregs, sizeof(struct vmrun_sregs)))
				goto out;

			r = 0;
			break;
		}

		case VMRUN_SET_SREGS: {
			vmrun_sregs = memdup_user(argp, sizeof(*vmrun_sregs));

			if (IS_ERR(vmrun_sregs)) {
				r = PTR_ERR(vmrun_sregs);
				vmrun_sregs = NULL;
				goto out;
			}

			r = vmrun_vcpu_ioctl_set_sregs(vcpu, vmrun_sregs);
			break;
		}
		
		default:
			return -EINVAL;
	}
out:
	vmrun_vcpu_put(vcpu);
	kfree(vmrun_sregs);
	return r;
}

static int vmrun_vcpu_fault(struct vm_fault *vmf)
{
	struct vmrun_vcpu *vcpu = vmf->vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff == 0)
		page = virt_to_page(vcpu->run);
//	else if (vmf->pgoff == VMRUN_PIO_PAGE_OFFSET)
//		page = virt_to_page(vcpu->arch.pio_data);
	else
		return VM_FAULT_SIGBUS;

	get_page(page);

	vmf->page = page;

	return 0;
}

static const struct vm_operations_struct vmrun_vcpu_vm_ops = {
	.fault = vmrun_vcpu_fault,
};

static int vmrun_vcpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &vmrun_vcpu_vm_ops;

	return 0;
}

static int vmrun_vcpu_release(struct inode *inode, struct file *filp)
{
	struct vmrun_vcpu *vcpu = filp->private_data;

	vmrun_put_vmrun(vcpu->vmrun);

	return 0;
}

static struct file_operations vmrun_vcpu_fops = {
	.release        = vmrun_vcpu_release,
	.unlocked_ioctl = vmrun_vcpu_ioctl,
	.mmap           = vmrun_vcpu_mmap,
	.llseek		= noop_llseek,
};

/*
 * Allocates an inode for the vcpu.
 */
static int vmrun_create_vcpu_fd(struct vmrun_vcpu *vcpu)
{
	return anon_inode_getfd("vmrun-vcpu", &vmrun_vcpu_fops, vcpu, O_RDWR | O_CLOEXEC);
}

/*
 * Creates some virtual cpus.  Good luck creating more than one. (!)
 */
static int vmrun_vm_ioctl_create_vcpu(struct vmrun *vmrun, u32 id)
{
	int r;
	struct vmrun_vcpu *vcpu;

	if (id >= VMRUN_MAX_VCPU_ID)
		return -EINVAL;

	mutex_lock(&vmrun->lock);

	if (vmrun->created_vcpus == VMRUN_MAX_VCPUS) {
		mutex_unlock(&vmrun->lock);
		return -EINVAL;
	}

	vmrun->created_vcpus++;

	mutex_unlock(&vmrun->lock);

	vcpu = vmrun_vcpu_create(vmrun, id);

	if (IS_ERR(vcpu)) {
		r = PTR_ERR(vcpu);
		goto vcpu_decrement;
	}

	preempt_notifier_init(&vcpu->preempt_notifier, &vmrun_preempt_ops);

	r = vmrun_vcpu_setup(vcpu);

	if (r)
		goto vcpu_destroy;

	mutex_lock(&vmrun->lock);
	
	if (vmrun_get_vcpu_by_id(vmrun, id)) {
		r = -EEXIST;
		goto unlock_vcpu_destroy;
	}

	BUG_ON(vmrun->vcpus[atomic_read(&vmrun->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	vmrun_get_vmrun(vmrun);
	
	r = vmrun_create_vcpu_fd(vcpu);
	
	if (r < 0) {
		vmrun_put_vmrun(vmrun);
		goto unlock_vcpu_destroy;
	}

	vmrun->vcpus[atomic_read(&vmrun->online_vcpus)] = vcpu;

	/*
	 * Pairs with smp_rmb() in vmrun_get_vcpu.  Write vmrun->vcpus
	 * before vmrun->online_vcpu's incremented value.
	 */
	smp_wmb();
	
	atomic_inc(&vmrun->online_vcpus);

	mutex_unlock(&vmrun->lock);
	
	return r;

unlock_vcpu_destroy:
	mutex_unlock(&vmrun->lock);
	
vcpu_destroy:
	vmrun_vcpu_destroy(vcpu);
	
vcpu_decrement:
	mutex_lock(&vmrun->lock);
	vmrun->created_vcpus--;
	mutex_unlock(&vmrun->lock);
	
	return r;
}

/*
 * Insert memslot and re-sort memslots based on their GFN,
 * so binary search could be used to lookup GFN.
 * Sorting algorithm takes advantage of having initially
 * sorted array and known changed memslot position.
 */
static void update_memslots(struct vmrun_memslots *slots,
			    struct vmrun_memory_slot *new)
{
	int id = new->id;
	int i = slots->id_to_index[id];
	struct vmrun_memory_slot *mslots = slots->memslots;

	WARN_ON(mslots[i].id != id);
	if (!new->npages) {
		WARN_ON(!mslots[i].npages);
		if (mslots[i].npages)
			slots->used_slots--;
	} else {
		if (!mslots[i].npages)
			slots->used_slots++;
	}

	while (i < VMRUN_MEM_SLOTS_NUM - 1 &&
	       new->base_gfn <= mslots[i + 1].base_gfn) {
		if (!mslots[i + 1].npages)
			break;
		mslots[i] = mslots[i + 1];
		slots->id_to_index[mslots[i].id] = i;
		i++;
	}

	/*
	 * The ">=" is needed when creating a slot with base_gfn == 0,
	 * so that it moves before all those with base_gfn == npages == 0.
	 *
	 * On the other hand, if new->npages is zero, the above loop has
	 * already left i pointing to the beginning of the empty part of
	 * mslots, and the ">=" would move the hole backwards in this
	 * case---which is wrong.  So skip the loop when deleting a slot.
	 */
	if (new->npages) {
		while (i > 0 &&
		       new->base_gfn >= mslots[i - 1].base_gfn) {
			mslots[i] = mslots[i - 1];
			slots->id_to_index[mslots[i].id] = i;
			i--;
		}
	} else
		WARN_ON_ONCE(i != slots->used_slots);

	mslots[i] = *new;
	slots->id_to_index[mslots[i].id] = i;
}

static int check_memory_region_flags(const struct vmrun_userspace_memory_region *mem)
{
	u32 valid_flags = VMRUN_MEM_LOG_DIRTY_PAGES;

#ifdef __VMRUN_HAVE_READONLY_MEM
	valid_flags |= VMRUN_MEM_READONLY;
#endif

	if (mem->flags & ~valid_flags)
		return -EINVAL;

	return 0;
}

static struct vmrun_memslots *install_new_memslots(struct vmrun *vmrun,
						 int as_id, struct vmrun_memslots *slots)
{
	struct vmrun_memslots *old_memslots = __vmrun_memslots(vmrun, as_id);

	/*
	 * Set the low bit in the generation, which disables SPTE caching
	 * until the end of synchronize_srcu_expedited.
	 */
	WARN_ON(old_memslots->generation & 1);
	slots->generation = old_memslots->generation + 1;

	rcu_assign_pointer(vmrun->memslots[as_id], slots);
	synchronize_srcu_expedited(&vmrun->srcu);

	/*
	 * Increment the new memslot generation a second time. This prevents
	 * vm exits that race with memslot updates from caching a memslot
	 * generation that will (potentially) be valid forever.
	 *
	 * Generations must be unique even across address spaces.  We do not need
	 * a global counter for that, instead the generation space is evenly split
	 * across address spaces.  For example, with two address spaces, address
	 * space 0 will use generations 0, 4, 8, ... while * address space 1 will
	 * use generations 2, 6, 10, 14, ...
	 */
	slots->generation += VMRUN_ADDRESS_SPACE_NUM * 2 - 1;

	vmrun_arch_memslots_updated(vmrun, slots);

	return old_memslots;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding vmrun->slots_lock for write.
 */
int __vmrun_set_memory_region(struct vmrun *vmrun,
			    const struct vmrun_userspace_memory_region *mem)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	struct vmrun_memory_slot *slot;
	struct vmrun_memory_slot old, new;
	struct vmrun_memslots *slots = NULL, *old_memslots;
	int as_id, id;
	enum vmrun_mr_change change;

	r = check_memory_region_flags(mem);
	if (r)
		goto out;

	r = -EINVAL;
	as_id = mem->slot >> 16;
	id = (u16)mem->slot;

	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	/* We can read the guest memory with __xxx_user() later on. */
	if ((id < VMRUN_USER_MEM_SLOTS) &&
	    ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
	     !access_ok(VERIFY_WRITE,
			(void __user *)(unsigned long)mem->userspace_addr,
			mem->memory_size)))
		goto out;
	if (as_id >= VMRUN_ADDRESS_SPACE_NUM || id >= VMRUN_MEM_SLOTS_NUM)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	slot = id_to_memslot(__vmrun_memslots(vmrun, as_id), id);
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

	if (npages > VMRUN_MEM_MAX_NR_PAGES)
		goto out;

	new = old = *slot;

	new.id = id;
	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	if (npages) {
		if (!old.npages)
			change = VMRUN_MR_CREATE;
		else { /* Modify an existing slot. */
			if ((mem->userspace_addr != old.userspace_addr) ||
			    (npages != old.npages) ||
			    ((new.flags ^ old.flags) & VMRUN_MEM_READONLY))
				goto out;

			if (base_gfn != old.base_gfn)
				change = VMRUN_MR_MOVE;
			else if (new.flags != old.flags)
				change = VMRUN_MR_FLAGS_ONLY;
			else { /* Nothing to change. */
				r = 0;
				goto out;
			}
		}
	} else {
		if (!old.npages)
			goto out;

		change = VMRUN_MR_DELETE;
		new.base_gfn = 0;
		new.flags = 0;
	}

	if ((change == VMRUN_MR_CREATE) || (change == VMRUN_MR_MOVE)) {
		/* Check for overlaps */
		r = -EEXIST;
		vmrun_for_each_memslot(slot, __vmrun_memslots(vmrun, as_id)) {
			if ((slot->id >= VMRUN_USER_MEM_SLOTS) ||
			    (slot->id == id))
				continue;
			if (!((base_gfn + npages <= slot->base_gfn) ||
			      (base_gfn >= slot->base_gfn + slot->npages)))
				goto out;
		}
	}

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & VMRUN_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = -ENOMEM;
	if (change == VMRUN_MR_CREATE) {
		new.userspace_addr = mem->userspace_addr;

		if (vmrun_arch_create_memslot(vmrun, &new, npages))
			goto out_free;
	}

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & VMRUN_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		if (vmrun_create_dirty_bitmap(&new) < 0)
			goto out_free;
	}

	slots = kvzalloc(sizeof(struct vmrun_memslots), GFP_KERNEL);
	if (!slots)
		goto out_free;
	memcpy(slots, __vmrun_memslots(vmrun, as_id), sizeof(struct vmrun_memslots));

	if ((change == VMRUN_MR_DELETE) || (change == VMRUN_MR_MOVE)) {
		slot = id_to_memslot(slots, id);
		slot->flags |= VMRUN_MEMSLOT_INVALID;

		old_memslots = install_new_memslots(vmrun, as_id, slots);

		/* From this point no new shadow pages pointing to a deleted,
		 * or moved, memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 *	- gfn_to_hva (vmrun_read_guest, gfn_to_pfn)
		 *	- vmrun_is_visible_gfn (mmu_check_roots)
		 */
		vmrun_arch_flush_shadow_memslot(vmrun, slot);

		/*
		 * We can re-use the old_memslots from above, the only difference
		 * from the currently installed memslots is the invalid flag.  This
		 * will get overwritten by update_memslots anyway.
		 */
		slots = old_memslots;
	}

	r = vmrun_arch_prepare_memory_region(vmrun, &new, mem, change);
	if (r)
		goto out_slots;

	/* actual memory is freed via old in vmrun_free_memslot below */
	if (change == VMRUN_MR_DELETE) {
		new.dirty_bitmap = NULL;
		memset(&new.arch, 0, sizeof(new.arch));
	}

	update_memslots(slots, &new);
	old_memslots = install_new_memslots(vmrun, as_id, slots);

	vmrun_arch_commit_memory_region(vmrun, mem, &old, &new, change);

	vmrun_free_memslot(vmrun, &old, &new);
	kvfree(old_memslots);
	return 0;

out_slots:
	kvfree(slots);

out_free:
	vmrun_free_memslot(vmrun, &new, &old);

out:
	return r;
}

int vmrun_set_memory_region(struct vmrun *vmrun,
			    const struct vmrun_userspace_memory_region *mem)
{
	int r;

	mutex_lock(&vmrun->slots_lock);
	r = __vmrun_set_memory_region(vmrun, mem);
	mutex_unlock(&vmrun->slots_lock);
	return r;
}

static int vmrun_vm_ioctl_set_memory_region(struct vmrun *vmrun,
					    struct vmrun_userspace_memory_region *mem)
{
	if ((u16)mem->slot >= VMRUN_USER_MEM_SLOTS)
		return -EINVAL;

	return vmrun_set_memory_region(vmrun, mem);
}

static long vmrun_vm_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct vmrun *vmrun = filp->private_data;
	void __user *argp   = (void __user *)arg;
	int r;

	if (vmrun->mm != current->mm)
		return -EIO;

	switch (ioctl) {
		case VMRUN_CREATE_VCPU:
			r = vmrun_vm_ioctl_create_vcpu(vmrun, arg);
			break;

		case VMRUN_SET_USER_MEMORY_REGION: {
			struct vmrun_userspace_memory_region vmrun_userspace_mem;
			r = -EFAULT;

			if (copy_from_user(&vmrun_userspace_mem,
					   argp,
					   sizeof(vmrun_userspace_mem)))
				goto out;

			r = vmrun_vm_ioctl_set_memory_region(vmrun, &vmrun_userspace_mem);
			break;
		}

		default:
			;
	}

out:
	return r;
}

#define vmrun_for_each_memslot(memslot, slots)	\
	for (memslot = &slots->memslots[0];	\
	      memslot < slots->memslots + VMRUN_MEM_SLOTS_NUM && memslot->npages;\
		memslot++)

//static bool vmrun_request_needs_ipi(struct vmrun_vcpu *vcpu, unsigned req)
//{
//	int mode = vmrun_vcpu_exiting_guest_mode(vcpu);
//
//	/*
//	 * We need to wait for the VCPU to reenable interrupts and get out of
//	 * READING_SHADOW_PAGE_TABLES mode.
//	 */
//	if (req & VMRUN_REQUEST_WAIT)
//		return mode != OUTSIDE_GUEST_MODE;
//
//	/*
//	 * Need to kick a running VCPU, but otherwise there is nothing to do.
//	 */
//	return mode == IN_GUEST_MODE;
//}
//
//static void ack_flush(void *_completed)
//{
//
//}
//
//static inline bool vmrun_kick_many_cpus(const struct cpumask *cpus, bool wait)
//{
//	if (unlikely(!cpus))
//		cpus = cpu_online_mask;
//
//	if (cpumask_empty(cpus))
//		return false;
//
//	smp_call_function_many(cpus, ack_flush, NULL, wait);
//
//	return true;
//}
//
//static inline void vmrun_make_request(int req, struct vmrun_vcpu *vcpu)
//{
//	/*
//	 * Ensure the rest of the request is published to vmrun_check_request's
//	 * caller.  Paired with the smp_mb__after_atomic in vmrun_check_request.
//	 */
//	smp_wmb();
//
//	set_bit(req & VMRUN_REQUEST_MASK, &vcpu->requests);
//}
//
//bool vmrun_make_all_cpus_request(struct vmrun *vmrun, unsigned int req)
//{
//	int i, cpu, me;
//	cpumask_var_t cpus;
//	bool called;
//	struct vmrun_vcpu *vcpu;
//
//	zalloc_cpumask_var(&cpus, GFP_ATOMIC);
//
//	me = get_cpu();
//	vmrun_for_each_vcpu(i, vcpu, vmrun) {
//		vmrun_make_request(req, vcpu);
//		cpu = vcpu->cpu;
//
//		if (!(req & VMRUN_REQUEST_NO_WAKEUP) && vmrun_vcpu_wake_up(vcpu))
//			continue;
//
//		if (cpus != NULL && cpu != -1 && cpu != me &&
//		    vmrun_request_needs_ipi(vcpu, req))
//			__cpumask_set_cpu(cpu, cpus);
//	}
//
//	called = vmrun_kick_many_cpus(cpus, !!(req & VMRUN_REQUEST_WAIT));
//	put_cpu();
//	free_cpumask_var(cpus);
//
//	return called;
//}

void vmrun_flush_remote_tlbs(struct vmrun *vmrun)
{
	/*
	 * Read tlbs_dirty before setting VMRUN_REQ_TLB_FLUSH in
	 * vmrun_make_all_cpus_request.
	 */
	long dirty_count = smp_load_acquire(&vmrun->tlbs_dirty);

	/*
	 * We want to publish modifications to the page tables before reading
	 * mode. Pairs with a memory barrier in arch-specific code.
	 * - x86: smp_mb__after_srcu_read_unlock in vcpu_enter_guest
	 * and smp_mb in walk_shadow_page_lockless_begin/end.
	 * - powerpc: smp_mb in vmrunppc_prepare_to_enter.
	 *
	 * There is already an smp_mb__after_atomic() before
	 * vmrun_make_all_cpus_request() reads vcpu->mode. We reuse that
	 * barrier here.
	 */
//	if (vmrun_make_all_cpus_request(vmrun, VMRUN_REQ_TLB_FLUSH))
//		++vmrun->stat.remote_tlb_flush;

	cmpxchg(&vmrun->tlbs_dirty, dirty_count, 0);
}

static inline struct vmrun *mmu_notifier_to_vmrun(struct mmu_notifier *mn)
{
	return container_of(mn, struct vmrun, mmu_notifier);
}

static void vmrun_mmu_notifier_change_pte(struct mmu_notifier *mn,
					  struct mm_struct *mm,
					  unsigned long address,
					  pte_t pte)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);
	int idx;

	idx = srcu_read_lock(&vmrun->srcu);

	spin_lock(&vmrun->mmu_lock);

	vmrun->mmu_notifier_seq++;

	vmrun_set_spte_hva(vmrun, address, pte);

	spin_unlock(&vmrun->mmu_lock);

	srcu_read_unlock(&vmrun->srcu, idx);
}

static void vmrun_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						      struct mm_struct *mm,
						      unsigned long start,
						      unsigned long end)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);
	int need_tlb_flush = 0, idx;

	idx = srcu_read_lock(&vmrun->srcu);

	spin_lock(&vmrun->mmu_lock);

	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	vmrun->mmu_notifier_count++;

	need_tlb_flush = vmrun_unmap_hva_range(vmrun, start, end);
	need_tlb_flush |= vmrun->tlbs_dirty;

	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		vmrun_flush_remote_tlbs(vmrun);

	spin_unlock(&vmrun->mmu_lock);

	srcu_read_unlock(&vmrun->srcu, idx);
}

static void vmrun_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    unsigned long start,
						    unsigned long end)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);

	spin_lock(&vmrun->mmu_lock);

	/*
	 * This sequence increase will notify the vmrun page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	vmrun->mmu_notifier_seq++;

	smp_wmb();

	/*
	 * The above sequence increase must be visible before the
	 * below count decrease, which is ensured by the smp_wmb above
	 * in conjunction with the smp_rmb in mmu_notifier_retry().
	 */
	vmrun->mmu_notifier_count--;

	spin_unlock(&vmrun->mmu_lock);

	BUG_ON(vmrun->mmu_notifier_count < 0);
}

static int vmrun_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					        struct mm_struct *mm,
					        unsigned long start,
					        unsigned long end)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);
	int young, idx;

	idx = srcu_read_lock(&vmrun->srcu);

	spin_lock(&vmrun->mmu_lock);

	young = vmrun_age_hva(vmrun, start, end);

	if (young)
		vmrun_flush_remote_tlbs(vmrun);

	spin_unlock(&vmrun->mmu_lock);

	srcu_read_unlock(&vmrun->srcu, idx);

	return young;
}

static int vmrun_mmu_notifier_clear_young(struct mmu_notifier *mn,
					  struct mm_struct *mm,
					  unsigned long start,
					  unsigned long end)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);
	int young, idx;

	idx = srcu_read_lock(&vmrun->srcu);

	spin_lock(&vmrun->mmu_lock);

	/*
	 * Even though we do not flush TLB, this will still adversely
	 * affect performance on pre-Haswell Intel EPT, where there is
	 * no EPT Access Bit to clear so that we have to tear down EPT
	 * tables instead. If we find this unacceptable, we can always
	 * add a parameter to vmrun_age_hva so that it effectively doesn't
	 * do anything on clear_young.
	 *
	 * Also note that currently we never issue secondary TLB flushes
	 * from clear_young, leaving this job up to the regular system
	 * cadence. If we find this inaccurate, we might come up with a
	 * more sophisticated heuristic later.
	 */
	young = vmrun_age_hva(vmrun, start, end);

	spin_unlock(&vmrun->mmu_lock);

	srcu_read_unlock(&vmrun->srcu, idx);

	return young;
}

static int vmrun_mmu_notifier_test_young(struct mmu_notifier *mn,
				         struct mm_struct *mm,
				         unsigned long address)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);
	int young, idx;

	idx = srcu_read_lock(&vmrun->srcu);

	spin_lock(&vmrun->mmu_lock);

	young = vmrun_test_age_hva(vmrun, address);

	spin_unlock(&vmrun->mmu_lock);

	srcu_read_unlock(&vmrun->srcu, idx);

	return young;
}

static void vmrun_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct vmrun *vmrun = mmu_notifier_to_vmrun(mn);
	int idx;

	idx = srcu_read_lock(&vmrun->srcu);

	// vmrun_arch_flush_shadow_all(vmrun);
	vmrun_mmu_invalidate_zap_all_pages(vmrun);

	srcu_read_unlock(&vmrun->srcu, idx);
}

static const struct mmu_notifier_ops vmrun_mmu_notifier_ops = {
	.invalidate_range_start	= vmrun_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= vmrun_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= vmrun_mmu_notifier_clear_flush_young,
	.clear_young		= vmrun_mmu_notifier_clear_young,
	.test_young		= vmrun_mmu_notifier_test_young,
	.change_pte		= vmrun_mmu_notifier_change_pte,
	.release		= vmrun_mmu_notifier_release,
};

static int vmrun_init_mmu_notifier(struct vmrun *vmrun)
{
	vmrun->mmu_notifier.ops = &vmrun_mmu_notifier_ops;

	return mmu_notifier_register(&vmrun->mmu_notifier, current->mm);
}

static struct vmrun_memslots *vmrun_alloc_memslots(void)
{
	int i;
	struct vmrun_memslots *slots;

	slots = kvzalloc(sizeof(struct vmrun_memslots), GFP_KERNEL);

	if (!slots)
		return NULL;

	for (i = 0; i < VMRUN_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = slots->memslots[i].id = i;

	return slots;
}

static void vmrun_destroy_dirty_bitmap(struct vmrun_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	kvfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = NULL;
}

void vmrun_page_track_free_memslot(struct vmrun_memory_slot *free,
				   struct vmrun_memory_slot *dont)
{
	int i;

	for (i = 0; i < VMRUN_PAGE_TRACK_MAX; i++)
		if (!dont || free->arch.gfn_track[i] !=
			     dont->arch.gfn_track[i]) {
			kvfree(free->arch.gfn_track[i]);
			free->arch.gfn_track[i] = NULL;
		}
}

void vmrun_arch_free_memslot(struct vmrun *vmrun,
			     struct vmrun_memory_slot *free,
			     struct vmrun_memory_slot *dont)
{
	int i;

	for (i = 0; i < VMRUN_NR_PAGE_SIZES; ++i) {
		if (!dont || free->arch.rmap[i] != dont->arch.rmap[i]) {
			kvfree(free->arch.rmap[i]);
			free->arch.rmap[i] = NULL;
		}
		if (i == 0)
			continue;

		if (!dont || free->arch.lpage_info[i - 1] !=
			     dont->arch.lpage_info[i - 1]) {
			kvfree(free->arch.lpage_info[i - 1]);
			free->arch.lpage_info[i - 1] = NULL;
		}
	}

	vmrun_page_track_free_memslot(free, dont);
}

/*
 * Free any memory in @free but not in @dont.
 */
static void vmrun_free_memslot(struct vmrun *vmrun, struct
			       vmrun_memory_slot *free,
			       struct vmrun_memory_slot *dont)
{
	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		vmrun_destroy_dirty_bitmap(free);

	vmrun_arch_free_memslot(vmrun, free, dont);

	free->npages = 0;
}

static void vmrun_free_memslots(struct vmrun *vmrun, struct vmrun_memslots *slots)
{
	struct vmrun_memory_slot *memslot;

	if (!slots)
		return;

	vmrun_for_each_memslot(memslot, slots)
		vmrun_free_memslot(vmrun, memslot, NULL);

	kvfree(slots);
}

static inline struct vmrun_memslots *__vmrun_memslots(struct vmrun *vmrun, int as_id)
{
	return srcu_dereference_check(vmrun->memslots[as_id], &vmrun->srcu,
				      lockdep_is_held(&vmrun->slots_lock) ||
				      !refcount_read(&vmrun->users_count));
}

static struct vmrun *vmrun_create_vm(unsigned long type)
{
	int r, i;

	struct vmrun *vmrun = kzalloc(sizeof(struct vmrun), GFP_KERNEL);

	if (!vmrun)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&vmrun->mmu_lock);
	mmgrab(current->mm);
	vmrun->mm = current->mm;
	mutex_init(&vmrun->lock);
	//mutex_init(&vmrun->irq_lock);
	mutex_init(&vmrun->slots_lock);
	refcount_set(&vmrun->users_count, 1);
	//INIT_LIST_HEAD(&vmrun->devices);

	if (type)
		r = -EINVAL;
		goto out_err_no_disable;

	INIT_HLIST_HEAD(&vmrun->mask_notifier_list);
	INIT_LIST_HEAD(&vmrun->active_mmu_pages);
	INIT_LIST_HEAD(&vmrun->zapped_obsolete_pages);
	INIT_LIST_HEAD(&vmrun->assigned_dev_head);
	atomic_set(&vmrun->noncoherent_dma_count, 0);

	vmrun_page_track_init(vmrun);
	vmrun_mmu_init_vm(vmrun);

	r = vmrun_cpu_enable_all();
	if (r)
		goto out_err_no_disable;

	BUILD_BUG_ON(VMRUN_MEM_SLOTS_NUM > SHRT_MAX);

	r = -ENOMEM;

	for (i = 0; i < VMRUN_ADDRESS_SPACE_NUM; i++) {
		struct vmrun_memslots *slots = vmrun_alloc_memslots();

		if (!slots)
			goto out_err_no_srcu;
		/*
		 * Generations must be different for each address space.
		 * Init vmrun generation close to the maximum to easily test the
		 * code of handling generation number wrap-around.
		 */

		slots->generation = i * 2 - 150;
		rcu_assign_pointer(vmrun->memslots[i], slots);
	}

	if (init_srcu_struct(&vmrun->srcu))
		goto out_err_no_srcu;

	r = vmrun_init_mmu_notifier(vmrun);
	if (r)
		goto out_err;

	spin_lock(&vmrun_lock);
	list_add(&vmrun->vm_list, &vm_list);
	spin_unlock(&vmrun_lock);

	preempt_notifier_inc();

	return vmrun;

out_err:
	cleanup_srcu_struct(&vmrun->srcu);

out_err_no_srcu:
	vmrun_cpu_disable_all();

out_err_no_disable:
	refcount_set(&vmrun->users_count, 0);
	
	for (i = 0; i < VMRUN_ADDRESS_SPACE_NUM; i++)
		vmrun_free_memslots(vmrun, __vmrun_memslots(vmrun, i));
	
	kfree(vmrun);
	mmdrop(current->mm);
	
	return ERR_PTR(r);
}

static inline struct vmrun_memory_slot *
id_to_memslot(struct vmrun_memslots *slots, int id)
{
	int index = slots->id_to_index[id];
	struct vmrun_memory_slot *slot;

	slot = &slots->memslots[index];

	WARN_ON(slot->id != id);
	
	return slot;
}

int __vmrun_set_memory_region(struct vmrun *vmrun, int id, gpa_t gpa, u32 size)
{
	int i, r;
	unsigned long hva;
	struct vmrun_memslots *slots = vmrun_memslots(vmrun);
	struct vmrun_memory_slot *slot, old;

	/* Called with vmrun->slots_lock held.  */
	if (WARN_ON(id >= VMRUN_MEM_SLOTS_NUM))
		return -EINVAL;

	slot = id_to_memslot(slots, id);
	
	if (size) {
		if (slot->npages)
			return -EEXIST;

		/*
		 * MAP_SHARED to prevent internal slot pages from being moved
		 * by fork()/COW.
		 */
		hva = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, 0);
		if (IS_ERR((void *)hva))
			return PTR_ERR((void *)hva);
	} else {
		if (!slot->npages)
			return 0;

		hva = 0;
	}

	old = *slot;
	
	for (i = 0; i < VMRUN_ADDRESS_SPACE_NUM; i++) {
		struct vmrun_userspace_memory_region m;

		m.slot = id | (i << 16);
		m.flags = 0;
		m.guest_phys_addr = gpa;
		m.userspace_addr = hva;
		m.memory_size = size;
		r = __vmrun_set_memory_region(vmrun, &m);
		if (r < 0)
			return r;
	}

	if (!size) {
		r = vm_munmap(old.userspace_addr, old.npages * PAGE_SIZE);
		WARN_ON(r < 0);
	}

	return 0;
}

int vmrun_set_memory_region(struct vmrun *vmrun, int id, gpa_t gpa, u32 size)
{
	int r;

	mutex_lock(&vmrun->slots_lock);
	r = __vmrun_set_memory_region(vmrun, id, gpa, size);
	mutex_unlock(&vmrun->slots_lock);

	return r;
}

static void vmrun_destroy_vm(struct vmrun *vmrun)
{
	int i;
	struct mm_struct *mm = vmrun->mm;

	spin_lock(&vmrun_lock);
	list_del(&vmrun->vm_list);
	spin_unlock(&vmrun_lock);

	mmu_notifier_unregister(&vmrun->mmu_notifier, vmrun->mm);

	if (current->mm == vmrun->mm) {
		/*
		 * Free memory regions allocated on behalf of userspace,
		 * unless the the memory map has changed due to process exit
		 * or fd copying.
		 */
		//vmrun_set_memory_region(vmrun, APIC_ACCESS_PAGE_PRIVATE_MEMSLOT, 0, 0);
		vmrun_set_memory_region(vmrun, IDENTITY_PAGETABLE_PRIVATE_MEMSLOT, 0, 0);
		//vmrun_set_memory_region(vmrun, TSS_PRIVATE_MEMSLOT, 0, 0);
	}
	
	vmrun_free_vcpus(vmrun);
	kvfree(rcu_dereference_check(vmrun->arch.apic_map, 1));
	vmrun_mmu_uninit_vm(vmrun);
	vmrun_page_track_cleanup(vmrun);

	//vmrun_destroy_devices(vmrun);

	for (i = 0; i < VMRUN_ADDRESS_SPACE_NUM; i++)
		vmrun_free_memslots(vmrun, __vmrun_memslots(vmrun, i));

	//cleanup_srcu_struct(&vmrun->irq_srcu);
	cleanup_srcu_struct(&vmrun->srcu);

	kfree(vmrun);
	preempt_notifier_dec();
	vmrun_cpu_disable_all();
	mmdrop(mm);
}

void vmrun_get_vmrun(struct vmrun *vmrun)
{
	refcount_inc(&vmrun->users_count);
}

void vmrun_put_vmrun(struct vmrun *vmrun)
{
	if (refcount_dec_and_test(&vmrun->users_count))
		vmrun_destroy_vm(vmrun);
}

static int vmrun_vm_release(struct inode *inode, struct file *filp)
{
	struct vmrun *vmrun = filp->private_data;

	vmrun_put_vmrun(vmrun);

	return 0;
}

static struct file_operations vmrun_vm_fops = {
	.release        = vmrun_vm_release,
	.unlocked_ioctl = vmrun_vm_ioctl,
	.llseek		= noop_llseek,
};

static int vmrun_dev_ioctl_create_vm(unsigned long type)
{
	int r;
	struct vmrun *vmrun;
	struct file *file;

	vmrun = vmrun_create_vm(type);

	if (IS_ERR(vmrun))
		return PTR_ERR(vmrun);

	r = get_unused_fd_flags(O_CLOEXEC);

	if (r < 0) {
		vmrun_put_vmrun(vmrun);
		return r;
	}

	file = anon_inode_getfile("vmrun-vm", &vmrun_vm_fops, vmrun, O_RDWR);

	if (IS_ERR(file)) {
		put_unused_fd(r);
		vmrun_put_vmrun(vmrun);
		return PTR_ERR(file);
	}

	fd_install(r, file);
	return r;
}

static long vmrun_dev_ioctl(struct file *filp,
			    unsigned int ioctl,
			    unsigned long arg)
{
	int r = -EINVAL;

	switch (ioctl) {
		case VMRUN_CREATE_VM:
			r = vmrun_dev_ioctl_create_vm(arg);
			break;
		case VMRUN_GET_VCPU_MMAP_SIZE:
			if (arg)
				goto out;
			r = PAGE_SIZE;     /* struct vmrun_run */
			r += PAGE_SIZE;    /* pio data page */
			break;

		default:
			return -EINVAL;
	}

out:
	return r;
}

static struct file_operations vmrun_chardev_ops = {
	.unlocked_ioctl = vmrun_dev_ioctl,
	.compat_ioctl   = vmrun_dev_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice vmrun_dev = {
	MISC_DYNAMIC_MINOR,
	"vmrun",
	&vmrun_chardev_ops,
};

static inline
struct vmrun_vcpu *vmrun_preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct vmrun_vcpu, preempt_notifier);
}

static void vmrun_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct vmrun_vcpu *vcpu = vmrun_preempt_notifier_to_vcpu(pn);

	if (vcpu->preempted)
		vcpu->preempted = false;

	vmrun_svm_vcpu_load(vcpu, cpu);
}

static void vmrun_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	struct vmrun_vcpu *vcpu = vmrun_preempt_notifier_to_vcpu(pn);

	if (current->state == TASK_RUNNING)
		vcpu->preempted = true;

	vmrun_svm_vcpu_put(vcpu);
}

static void vmrun_cpu_enable_nolock(void *junk)
{
	struct vmrun_cpu_data *cd;
	struct desc_struct *gdt;
	int cpu = raw_smp_processor_id();
	uint64_t efer;
	int r;

	if (cpumask_test_cpu(cpu, cpus_enabled))
		return;

	cpumask_set_cpu((unsigned int)cpu, cpus_enabled);

	if (vmrun_svm_check()) {
		r = -EBUSY;
		goto err;
	}

	if (!vmrun_has_svm()) {
		printk("cpu_enable: SVM is not supported and enabled on CPU %d\n", cpu);
		r = -EINVAL;
		goto err;
	}

	cd = per_cpu(cpu_data, me);

	if (!cd) {
		pr_err("%s: cpu_data is NULL on CPU %d\n", __func__, cpu);
		r = -EINVAL;
		goto err;
	}

	asm volatile("cpuid\n\t" : "=b" (cd->max_asid)
				 : "a" (CPUID_EXT_A_SVM_LOCK_LEAF)
				 : "%rcx","%rdx");

	cd->max_asid--;
	cd->next_asid = cd->max_asid + 1;
	cd->asid_generation = 1;

	printk("cpu_enable: Initialized ASID on CPU %d\n", me);

	// Alternative to the code below for TSS desc registration
	//
	// struct desc_ptr gdt_descr;
	// asm volatile("sgdt %0" : "=m" (gdt_descr));
	// gdt = (struct desc_struct *)gdt_descr.address;

	gdt = this_cpu_ptr(&gdt_page)->gdt;
	cd->tss_desc = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);

	printk("cpu_enable: Registered TSS descriptor on CPU %d\n", me);

	vmrun_svm_enable();

	printk("cpu_enable: Enabled SVM on CPU %d\n", me);

	asm volatile("wrmsr\n\t" :
				 : "c" (MSR_VM_HSAVE_PA), "A" (page_to_pfn(cd->save_area) << PAGE_SHIFT)
				 :);

	printk("cpu_setup: Registered host save area on CPU %d\n", me);

	return;

err:
	cpumask_clear_cpu(cpu, cpus_enabled);
	atomic_inc(&cpu_enable_failed);
	pr_info("cpu_enable_nolock: enabling virtualization on CPU %d failed\n", cpu);
}

static int vmrun_cpu_enable(unsigned int cpu)
{
	raw_spin_lock(&vmrun_count_lock);

	if (vmrun_usage_count)
		vmrun_cpu_enable_nolock(NULL);

	raw_spin_unlock(&vmrun_count_lock);

	return 0;
}

static void vmrun_cpu_disable_nolock(void *junk)
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

	vmrun_svm_disable();

	printk("cpu_disable: Disabled SVM on CPU %d\n", cpu);
}

static int vmrun_cpu_disable(unsigned int cpu)
{
	raw_spin_lock(&vmrun_count_lock);

	if (vmrun_usage_count)
		vmrun_cpu_disable_nolock(NULL);

	raw_spin_unlock(&vmrun_count_lock);

	return 0;
}

static void vmrun_cpu_disable_all_nolock(void)
{
	BUG_ON(!vmrun_usage_count);

	vmrun_usage_count--;

	if (!vmrun_usage_count)
		on_each_cpu(vmrun_cpu_disable_nolock, NULL, 1);
}

static void vmrun_cpu_disable_all(void)
{
	raw_spin_lock(&vmrun_count_lock);

	vmrun_cpu_disable_all_nolock();

	raw_spin_unlock(&vmrun_count_lock);
}

static int vmrun_cpu_enable_all(void)
{
	int r = 0;

	raw_spin_lock(&vmrun_count_lock);

	vmrun_usage_count++;
	if (vmrun_usage_count == 1) {
		atomic_set(&cpu_enable_failed, 0);
		on_each_cpu(vmrun_cpu_enable_nolock, NULL, 1);

		if (atomic_read(&cpu_enable_failed)) {
			vmrun_cpu_disable_all_nolock();
			r = -EBUSY;
		}
	}

	raw_spin_unlock(&vmrun_count_lock);

	return r;
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

	if (!cd->save_area) {
		r = -ENOMEM;
		goto err;
	}

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
	// and we can use either.

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

	r = vmrun_iopm_allocate();
	if (r)
		goto out_free_cpumask;

	for_each_possible_cpu(cpu) {
		r = vmrun_cpu_setup(cpu);

		if (r)
			goto out_free_iopm;
	}

	r = cpuhp_setup_state_nocalls(CPUHP_AP_VMRUN_STARTING, "vmrun/cpu:enable",
				      vmrun_cpu_enable, vmrun_cpu_disable);
	if (r) {
		printk(KERN_ERR "vmrun_init: CPU enable failed\n");
		goto out_free_cpus;
	}

	vmrun_chardev_ops.owner = THIS_MODULE;

	r = misc_register(&vmrun_dev);

	if (r) {
		printk(KERN_ERR "vmrun_init: Misc device register failed\n");
		goto out_free_hp;
	}

	vmrun_preempt_ops.sched_in  = vmrun_sched_in;
	vmrun_preempt_ops.sched_out = vmrun_sched_out;

	printk("vmrun_init: Done\n");
	
	return r;

out_free_hp:
	cpuhp_remove_state_nocalls(CPUHP_AP_VMRUN_STARTING);

out_free_cpus:
	for_each_possible_cpu(cpu)
		vmrun_cpu_unsetup(cpu);

out_free_iopm:
	vmrun_iopm_free();

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

	cpuhp_remove_state_nocalls(CPUHP_AP_VMRUN_STARTING);

	on_each_cpu(vmrun_cpu_disable_nolock, NULL, 1);

	for_each_possible_cpu(cpu)
		vmrun_cpu_unsetup(cpu);

	vmrun_iopm_free();

	free_cpumask_var(cpus_enabled);

	printk("vmrun_exit: Done\n");
}

module_init(vmrun_init);
module_exit(vmrun_exit);
