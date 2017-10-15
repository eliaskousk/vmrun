#ifndef VMRUN_TYPES_H
#define VMRUN_TYPES_H

#include <linux/types.h>

struct vmrun;
struct vmrun_vcpu;
struct vmrun_memory_slot;

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
typedef u64            gfn_t;

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

typedef hfn_t          vmrun_pfn_t;

#endif //VMRUN_TYPES_H
