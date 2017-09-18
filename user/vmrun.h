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
// Copyright (C) 2017 STROMASYS SA (http://www.stromasys.com)
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

#ifndef VMRUN_USER_H
#define VMRUN_USER_H

// User-space interface for /dev/vmrun

#include <asm/types.h>
#include <linux/ioctl.h>

#define VMRUNIO 0xAEE // TODO: Check validity

#define VMRUN_VCPU_CREATE           	_IOW(VMRUNIO,  1, int /* vcpu_slot */)
#define VMRUN_VCPU_RUN              	_IOWR(VMRUNIO, 2, struct vmrun_run)
#define VMRUN_GET_REGS              	_IOWR(VMRUNIO, 3, struct vmrun_regs)
#define VMRUN_SET_REGS              	_IOW(VMRUNIO,  4, struct vmrun_regs)
#define VMRUN_GET_SREGS             	_IOWR(VMRUNIO, 5, struct vmrun_sregs)
#define VMRUN_SET_SREGS          	_IOW(VMRUNIO,  6, struct vmrun_sregs)
#define VMRUN_SET_USER_MEMORY_REGION	_IOW(VMRUNIO,  7, struct vmrun_memory_region)

#define VMRUN_EXIT_TYPE_FAIL_ENTRY 1
#define VMRUN_EXIT_TYPE_VM_EXIT    2

/*
 * Architectural interrupt line count, and the size of the bitmap needed
 * to hold them.
 */
#define VMRUN_NR_INTERRUPTS		256
#define VMRUN_IRQ_BITMAP_SIZE_BYTES	((VMRUN_NR_INTERRUPTS + 7) / 8)
#define VMRUN_IRQ_BITMAP_SIZE(type)	(VMRUN_IRQ_BITMAP_SIZE_BYTES / sizeof(type))

/* For vmrun_memory_region::flags */
#define VMRUN_MEM_LOG_DIRTY_PAGES	1UL

enum vmrun_exit_reason {
	VMRUN_EXIT_UNKNOWN          = 0,
	VMRUN_EXIT_EXCEPTION        = 1,
	VMRUN_EXIT_IO               = 2,
	VMRUN_EXIT_CPUID            = 3,
	VMRUN_EXIT_DEBUG            = 4,
	VMRUN_EXIT_HLT              = 5,
	VMRUN_EXIT_MMIO             = 6,
};

/* for VMRUN_RUN */
struct vmrun_run {
	/* in */
	__u32 vcpu;
	__u32 emulated;  /* skip current instruction */
	__u32 mmio_completed; /* mmio request completed */

	/* out */
	__u32 exit_type;
	__u32 exit_reason;
	__u32 instruction_length;
	union {
		/* VMRUN_EXIT_UNKNOWN */
		struct {
			__u32 hardware_exit_reason;
		} hw;
		/* VMRUN_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* VMRUN_EXIT_IO */
		struct {
#define VMRUN_EXIT_IO_IN  0
#define VMRUN_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u8 string;
			__u8 string_down;
			__u8 rep;
			__u8 pad;
			__u16 port;
			__u64 count;
			union {
				__u64 address;
				__u32 value;
			};
		} io;
		struct {
		} debug;
		/* VMRUN_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
	};
};

struct vmrun_regs {
	/* in */
	__u32 vcpu;
	__u32 padding;

	/* out (VMRUN_GET_REGS) / in (VMRUN_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

struct vmrun_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

struct vmrun_dtable {
	__u64 base;
	__u16 limit;
	__u16 padding[3];
};

struct vmrun_sregs {
	/* in */
	__u32 vcpu;
	__u32 padding;

	/* out (VMRUN_GET_SREGS) / in (VMRUN_SET_SREGS) */
	struct vmrun_segment cs, ds, es, fs, gs, ss;
	struct vmrun_segment tr, ldt;
	struct vmrun_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
	__u64 efer;
	__u64 apic_base;
	__u64 interrupt_bitmap[VMRUN_IRQ_BITMAP_SIZE(__u64)];
};

/* for VMRUN_CREATE_MEMORY_REGION */
struct vmrun_memory_region {
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
};

#endif /* VMRUN_USER */
