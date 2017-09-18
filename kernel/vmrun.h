//
// =========================================================
// x86 Hardware Assisted Virtualization Demo for AMD-V (SVM)
// =========================================================
//
// Description: A very basic driver and associated user app
// that walks through all the steps to do a successful vmrun.
// After vmrun, the guest code does a vmmcall and #vmexits
// back to the host. The guest state mirrors the host.
//
// References for study:
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
// Copyright (C) 2017 STROMASYS SA <http://www.stromasys.com>
// Copyright (C) 2006 Qumranet, Inc.
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

#ifndef VMRUN_H
#define VMRUN_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#define CPUID_EXT_1_SVM_LEAF      0x80000001
#define CPUID_EXT_1_SVM_BIT       0x2
#define CPUID_EXT_A_SVM_LOCK_LEAF 0x8000000a
#define CPUID_EXT_A_SVM_LOCK_BIT  0x2

#define MSR_VM_CR_SVM_DIS_ADDR    0xc0010114
#define MSR_VM_CR_SVM_DIS_BIT     0x4
#define MSR_EFER_SVM_EN_ADDR      0xc0000080
#define MSR_EFER_SVM_EN_BIT       0xC
#define MSR_VM_HSAVE_PA           0xc0010117

#define HF_GIF_MASK		  (1 << 0)
#define V_INTR_MASK               (1 << 24)

#define IOPM_ALLOC_ORDER          2
#define MSRPM_ALLOC_ORDER         1

#define SEG_TYPE_LDT              2
#define SEG_TYPE_AVAIL_TSS64      9

#define INVALID_PAGE              (~(hpa_t)0)

#define VMRUN_MAX_VCPUS           1
#define VMRUN_MEMORY_SLOTS        4

#define INSTR_SVM_VMRUN           ".byte 0x0f, 0x01, 0xd8"
#define INSTR_SVM_VMMCALL         ".byte 0x0f, 0x01, 0xd9"
#define INSTR_SVM_VMLOAD          ".byte 0x0f, 0x01, 0xda"
#define INSTR_SVM_VMSAVE          ".byte 0x0f, 0x01, 0xdb"
#define INSTR_SVM_STGI            ".byte 0x0f, 0x01, 0xdc"
#define INSTR_SVM_CLGI            ".byte 0x0f, 0x01, 0xdd"

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef unsigned long  gfn_t;

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef unsigned long  hfn_t;

enum {
	VMCB_INTERCEPTS, /* Intercept vectors, TSC offset,
			    pause filter count */
	VMCB_PERM_MAP,   /* IOPM Base and MSRPM Base */
	VMCB_ASID,	 /* ASID */
	VMCB_INTR,	 /* int_ctl, int_vector */
	VMCB_NPT,        /* npt_en, nCR3, gPAT */
	VMCB_CR,	 /* CR0, CR3, CR4, EFER */
	VMCB_DR,         /* DR6, DR7 */
	VMCB_DT,         /* GDT, IDT */
	VMCB_SEG,        /* CS, DS, SS, ES, CPL */
	VMCB_CR2,        /* CR2 only */
	VMCB_LBR,        /* DBGCTL, BR_FROM, BR_TO, LAST_EX_FROM, LAST_EX_TO */
	VMCB_AVIC,       /* AVIC APIC_BAR, AVIC APIC_BACKING_PAGE,
			  * AVIC PHYSICAL_TABLE pointer,
			  * AVIC LOGICAL_TABLE pointer
			  */
	VMCB_DIRTY_MAX,
};

enum reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};

struct ldttss_desc {
	u16 limit0;
	u16 base0;
	unsigned base1:8, type:5, dpl:2, p:1;
	unsigned limit1:4, zero0:3, g:1, base2:8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

struct vmrun_cpu_data {
	int cpu;
	u64 asid_generation;
	u32 max_asid;
	u32 next_asid;
	struct ldttss_desc *tss_desc;
	struct page *save_area;
};

struct vmrun_mmu {
	void (*new_cr3)(struct vmrun_vcpu *vcpu);
	int (*page_fault)(struct vmrun_vcpu *vcpu, gva_t gva, u32 err);
	void (*inval_page)(struct vmrun_vcpu *vcpu, gva_t gva);
	void (*free)(struct vmrun_vcpu *vcpu);
	gpa_t (*gva_to_gpa)(struct vmrun_vcpu *vcpu, gva_t gva);
	hpa_t root_hpa;
	int root_level;
	int shadow_root_level;
};

struct vmrun_memory_slot {
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long flags;
	struct page **phys_mem;
	unsigned long *dirty_bitmap;
};

struct vmrun_vcpu {
	struct vmrun *vmrun;
	struct mutex mutex;
	int cpu;
	int vcpu_id;
	struct vmcb *vmcb;
	unsigned long vmcb_pa;
	struct vmrun_cpu_data *cpu_data;
	uint64_t asid_generation;
	unsigned long cr0;
	u32 hflags;
	u64 efer;
	u64 next_rip;
	u32 *msrpm;
	unsigned long regs[NR_VCPU_REGS];
	struct vmrun_mmu mmu;
	struct list_head free_pages;
};

struct vmrun {
	spinlock_t lock; /* protects everything except vcpus */
	int nmemslots;
	struct vmrun_memory_slot memslots[VMRUN_MEMORY_SLOTS];
	struct list_head active_mmu_pages;
	struct vmrun_vcpu vcpus[VMRUN_MAX_VCPUS];
	int memory_config_version;
	int busy;
};

#endif // VMRUN_H
