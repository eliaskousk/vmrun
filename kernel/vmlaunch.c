// =======
// Control
// =======

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

// ================
// Host Guest State
// ================

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
