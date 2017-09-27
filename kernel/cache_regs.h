#ifndef ASM_KVM_CACHE_REGS_H
#define ASM_KVM_CACHE_REGS_H

#include "vmrun.h"

#define KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define KVM_POSSIBLE_CR4_GUEST_BITS				  \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR  \
	 | X86_CR4_OSXMMEXCPT | X86_CR4_LA57 | X86_CR4_PGE)

static inline unsigned long vmrun_register_read(struct vmrun_vcpu *vcpu,
					        enum vmrun_reg reg)
{
	if (!test_bit(reg, (unsigned long *)&vcpu->regs_avail))
		vmrun_x86_ops->cache_reg(vcpu, reg);

	return vcpu->regs[reg];
}

static inline void vmrun_register_write(struct vmrun_vcpu *vcpu,
				        enum vmrun_reg reg,
				        unsigned long val)
{
	vcpu->regs[reg] = val;
	__set_bit(reg, (unsigned long *)&vcpu->regs_dirty);
	__set_bit(reg, (unsigned long *)&vcpu->regs_avail);
}

static inline unsigned long vmrun_rip_read(struct vmrun_vcpu *vcpu)
{
	return vmrun_register_read(vcpu, VCPU_REGS_RIP);
}

static inline void vmrun_rip_write(struct vmrun_vcpu *vcpu, unsigned long val)
{
	vmrun_register_write(vcpu, VCPU_REGS_RIP, val);
}

static inline u64 vmrun_pdptr_read(struct vmrun_vcpu *vcpu, int index)
{
	might_sleep();  /* on svm */

	if (!test_bit(VCPU_EXREG_PDPTR,
		      (unsigned long *)&vcpu->arch.regs_avail))
		vmrun_x86_ops->cache_reg(vcpu, VCPU_EXREG_PDPTR);

	return vcpu->arch.walk_mmu->pdptrs[index];
}

static inline ulong vmrun_read_cr0_bits(struct vmrun_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR0_GUEST_BITS;
	if (tmask & vcpu->arch.cr0_guest_owned_bits)
		vmrun_x86_ops->decache_cr0_guest_bits(vcpu);
	return vcpu->arch.cr0 & mask;
}

static inline ulong vmrun_read_cr0(struct vmrun_vcpu *vcpu)
{
	return vmrun_read_cr0_bits(vcpu, ~0UL);
}

static inline ulong vmrun_read_cr4_bits(struct vmrun_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR4_GUEST_BITS;
	if (tmask & vcpu->arch.cr4_guest_owned_bits)
		vmrun_x86_ops->decache_cr4_guest_bits(vcpu);
	return vcpu->arch.cr4 & mask;
}

static inline ulong vmrun_read_cr3(struct vmrun_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail))
		vmrun_x86_ops->decache_cr3(vcpu);
	return vcpu->arch.cr3;
}

static inline ulong vmrun_read_cr4(struct vmrun_vcpu *vcpu)
{
	return vmrun_read_cr4_bits(vcpu, ~0UL);
}

static inline u64 vmrun_read_edx_eax(struct vmrun_vcpu *vcpu)
{
	return (vmrun_register_read(vcpu, VCPU_REGS_RAX) & -1u)
		| ((u64)(vmrun_register_read(vcpu, VCPU_REGS_RDX) & -1u) << 32);
}

static inline void enter_guest_mode(struct vmrun_vcpu *vcpu)
{
	vcpu->arch.hflags |= HF_GUEST_MASK;
}

static inline void leave_guest_mode(struct vmrun_vcpu *vcpu)
{
	vcpu->arch.hflags &= ~HF_GUEST_MASK;
}

static inline bool is_guest_mode(struct vmrun_vcpu *vcpu)
{
	return vcpu->arch.hflags & HF_GUEST_MASK;
}

static inline bool is_smm(struct vmrun_vcpu *vcpu)
{
	return vcpu->arch.hflags & HF_SMM_MASK;
}

#endif
