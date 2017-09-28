#ifndef VMRUN_CACHE_REGS_H
#define VMRUN_CACHE_REGS_H

#include "vmrun.h"

static inline unsigned long vmrun_register_read(struct vmrun_vcpu *vcpu,
					        enum vmrun_reg reg)
{
	if (!test_bit(reg, (unsigned long *)&vcpu->regs_avail))
		BUG();

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

static inline ulong vmrun_read_cr0_bits(struct vmrun_vcpu *vcpu, ulong mask)
{
	return vcpu->cr0 & mask;
}

static inline ulong vmrun_read_cr0(struct vmrun_vcpu *vcpu)
{
	return vmrun_read_cr0_bits(vcpu, ~0UL);
}

static inline ulong vmrun_read_cr4_bits(struct vmrun_vcpu *vcpu, ulong mask)
{
	return vcpu->cr4 & mask;
}

static inline ulong vmrun_read_cr3(struct vmrun_vcpu *vcpu)
{
	return vcpu->cr3;
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
	vcpu->hflags |= HF_GUEST_MASK;
}

static inline void leave_guest_mode(struct vmrun_vcpu *vcpu)
{
	vcpu->hflags &= ~HF_GUEST_MASK;
}

static inline bool is_guest_mode(struct vmrun_vcpu *vcpu)
{
	return vcpu->hflags & HF_GUEST_MASK;
}

static inline bool is_smm(struct vmrun_vcpu *vcpu)
{
	return vcpu->hflags & HF_SMM_MASK;
}

#endif // VMRUN_CACHE_REGS
