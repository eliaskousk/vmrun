#ifndef _ASM_X86_VMRUN_PAGE_TRACK_H
#define _ASM_X86_VMRUN_PAGE_TRACK_H

enum vmrun_page_track_mode {
	VMRUN_PAGE_TRACK_WRITE,
	VMRUN_PAGE_TRACK_MAX,
};

/*
 * The notifier represented by @vmrun_page_track_notifier_node is linked into
 * the head which will be notified when guest is triggering the track event.
 *
 * Write access on the head is protected by vmrun->mmu_lock, read access
 * is protected by track_srcu.
 */
struct vmrun_page_track_notifier_head {
	struct srcu_struct track_srcu;
	struct hlist_head track_notifier_list;
};

struct vmrun_page_track_notifier_node {
	struct hlist_node node;

	/*
	 * It is called when guest is writing the write-tracked page
	 * and write emulation is finished at that time.
	 *
	 * @vcpu: the vcpu where the write access happened.
	 * @gpa: the physical address written by guest.
	 * @new: the data was written to the address.
	 * @bytes: the written length.
	 * @node: this node
	 */
	void (*track_write)(struct vmrun_vcpu *vcpu, gpa_t gpa, const u8 *new,
			    int bytes, struct vmrun_page_track_notifier_node *node);
	/*
	 * It is called when memory slot is being moved or removed
	 * users can drop write-protection for the pages in that memory slot
	 *
	 * @vmrun: the vmrun where memory slot being moved or removed
	 * @slot: the memory slot being moved or removed
	 * @node: this node
	 */
	void (*track_flush_slot)(struct vmrun *vmrun, struct vmrun_memory_slot *slot,
			    struct vmrun_page_track_notifier_node *node);
};

void vmrun_page_track_init(struct vmrun *vmrun);
void vmrun_page_track_cleanup(struct vmrun *vmrun);

void vmrun_page_track_free_memslot(struct vmrun_memory_slot *free,
				 struct vmrun_memory_slot *dont);
int vmrun_page_track_create_memslot(struct vmrun_memory_slot *slot,
				  unsigned long npages);

void vmrun_slot_page_track_add_page(struct vmrun *vmrun,
				  struct vmrun_memory_slot *slot, gfn_t gfn,
				  enum vmrun_page_track_mode mode);
void vmrun_slot_page_track_remove_page(struct vmrun *vmrun,
				     struct vmrun_memory_slot *slot, gfn_t gfn,
				     enum vmrun_page_track_mode mode);
bool vmrun_page_track_is_active(struct vmrun_vcpu *vcpu, gfn_t gfn,
			      enum vmrun_page_track_mode mode);

void
vmrun_page_track_register_notifier(struct vmrun *vmrun,
				 struct vmrun_page_track_notifier_node *n);
void
vmrun_page_track_unregister_notifier(struct vmrun *vmrun,
				   struct vmrun_page_track_notifier_node *n);
void vmrun_page_track_write(struct vmrun_vcpu *vcpu, gpa_t gpa, const u8 *new,
			  int bytes);
void vmrun_page_track_flush_slot(struct vmrun *vmrun, struct vmrun_memory_slot *slot);
#endif
