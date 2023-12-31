#ifndef __ARCH_ARM_NUMA_H
#define __ARCH_ARM_NUMA_H

#include <xen/mm.h>

typedef u8 nodeid_t;

#ifndef CONFIG_NUMA

/* Fake one node for now. See also node_online_map. */
#define cpu_to_node(cpu) 0
#define node_to_cpumask(node)   (cpu_online_map)

/* XXX: implement NUMA support */
#define node_spanned_pages(nid) (max_page - mfn_x(first_valid_mfn))
#define node_start_pfn(nid) (mfn_x(first_valid_mfn))
#define __node_distance(a, b) (20)

#endif

#define arch_want_default_dmazone() (false)

#endif /* __ARCH_ARM_NUMA_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
