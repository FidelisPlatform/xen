#ifndef _DOM0_BUILD_H_
#define _DOM0_BUILD_H_

#include <xen/bootinfo.h>
#include <xen/libelf.h>
#include <xen/sched.h>

#include <asm/setup.h>

extern unsigned int dom0_memflags;

unsigned long dom_avail_nr_pages(
    struct boot_domain *bd, nodemask_t nodes);

unsigned long dom0_compute_nr_pages(
    struct boot_domain *bd, struct elf_dom_parms *parms,
    unsigned long initrd_len);

unsigned long dom_compute_nr_pages(
    struct boot_domain *bd, struct elf_dom_parms *parms,
    unsigned long initrd_len);

int dom0_setup_permissions(struct domain *d);

void dom0_pvh_setup_e820(struct domain *d, unsigned long nr_pages);
int dom0_construct_pvh(struct boot_domain *bd);

unsigned long dom0_paging_pages(const struct domain *d,
                                unsigned long nr_pages);

int pvh_populate_memory_range(
    struct domain *d, unsigned long start, unsigned long nr_pages);
int pvh_populate_p2m(struct domain *d);

int pvh_steal_ram(
    struct domain *d, unsigned long size, unsigned long align, paddr_t limit,
    paddr_t *addr);
int pvh_add_mem_range(
    struct domain *d, uint64_t s, uint64_t e, unsigned int type);

int pvh_setup_acpi(struct domain *d, paddr_t start_info);

void pvh_setup_mmcfg(struct domain *d);

int pvh_load_kernel(
    struct domain *d, const struct boot_module *image,
    struct boot_module *initrd, void *image_base, char *cmdline,
    paddr_t *entry, paddr_t *start_info_addr);

void dom_update_physmap(bool compat, unsigned long pfn,
                         unsigned long mfn, unsigned long vphysmap_s);

#endif	/* _DOM0_BUILD_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
