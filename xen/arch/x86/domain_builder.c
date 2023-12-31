#include <xen/bootdomain.h>
#include <xen/bootinfo.h>
#include <xen/domain.h>
#include <xen/domain_builder.h>
#include <xen/err.h>
#include <xen/grant_table.h>
#include <xen/iommu.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/cpu-policy.h>
#include <asm/pv/shim.h>
#include <asm/dom0_build.h>
#include <asm/setup.h>
#include <asm/spec_ctrl.h>

extern unsigned long cr4_pv32_mask;

static unsigned int __init dom_max_vcpus(struct boot_domain *bd)
{
    unsigned int limit;

    if ( builder_is_initdom(bd) )
        return dom0_max_vcpus();

    limit = bd->mode & BUILD_MODE_PARAVIRTUALIZED ?
                MAX_VIRT_CPUS : HVM_MAX_VCPUS;

    if ( bd->ncpus > limit )
        return limit;
    else
        return bd->ncpus;
}

struct vcpu *__init alloc_dom_vcpu0(struct boot_domain *bd)
{
    if ( bd->functions & BUILD_FUNCTION_INITIAL_DOM )
        return alloc_dom0_vcpu0(bd->domain);

    bd->domain->node_affinity = node_online_map;
    bd->domain->auto_node_affinity = true;

    return vcpu_create(bd->domain, 0);
}


unsigned long __init dom_avail_nr_pages(
    struct boot_domain *bd, nodemask_t nodes)
{
    unsigned long avail = 0, iommu_pages = 0;
    bool is_ctldom = false, is_hwdom = false;
    unsigned long nr_pages = bd->meminfo.mem_size.nr_pages;
    nodeid_t node;

    if ( builder_is_ctldom(bd) )
        is_ctldom = true;
    if ( builder_is_hwdom(bd) )
        is_hwdom = true;

    for_each_node_mask ( node, nodes )
        avail += avail_domheap_pages_region(node, 0, 0) +
                 initial_images_nrpages(node);

    /* Reserve memory for further dom0 vcpu-struct allocations... */
    avail -= (bd->domain->max_vcpus - 1UL)
             << get_order_from_bytes(sizeof(struct vcpu));
    /* ...and compat_l4's, if needed. */
    if ( is_pv_32bit_domain(bd->domain) )
        avail -= bd->domain->max_vcpus - 1;

    /* Reserve memory for iommu_dom0_init() (rough estimate). */
    if ( is_hwdom && is_iommu_enabled(bd->domain) && !iommu_hwdom_passthrough )
    {
        unsigned int s;

        for ( s = 9; s < BITS_PER_LONG; s += 9 )
            iommu_pages += max_pdx >> s;

        avail -= iommu_pages;
    }

    if ( paging_mode_enabled(bd->domain) ||
         (is_ctldom && opt_dom0_shadow) ||
         (is_hwdom && opt_pv_l1tf_hwdom) )
    {
        unsigned long cpu_pages = dom0_paging_pages(bd->domain, nr_pages);

        if ( !iommu_use_hap_pt(bd->domain) )
            avail -= cpu_pages;
        else if ( cpu_pages > iommu_pages )
            avail -= cpu_pages - iommu_pages;
    }

    return avail;
}

unsigned long __init dom_compute_nr_pages(
    struct boot_domain *bd, struct elf_dom_parms *parms,
    unsigned long initrd_len)
{
    unsigned long avail, nr_pages = bd->meminfo.mem_size.nr_pages;

    if ( builder_is_initdom(bd) )
        return dom0_compute_nr_pages(bd, parms, initrd_len);

    avail = dom_avail_nr_pages(bd, node_online_map);

    if ( is_pv_domain(bd->domain) && (parms->p2m_base == UNSET_ADDR) )
    {
        /*
         * Legacy Linux kernels (i.e. such without a XEN_ELFNOTE_INIT_P2M
         * note) require that there is enough virtual space beyond the initial
         * allocation to set up their initial page tables. This space is
         * roughly the same size as the p2m table, so make sure the initial
         * allocation doesn't consume more than about half the space that's
         * available between params.virt_base and the address space end.
         */
        unsigned long vstart, vend, end;
        size_t sizeof_long = is_pv_32bit_domain(bd->domain) ?
                             sizeof(int) : sizeof(long);

        vstart = parms->virt_base;
        vend = round_pgup(parms->virt_kend);
        if ( !parms->unmapped_initrd )
            vend += round_pgup(initrd_len);
        end = vend + nr_pages * sizeof_long;

        if ( end > vstart )
            end += end - vstart;
        if ( end <= vstart ||
             (sizeof_long < sizeof(end) && end > (1UL << (8 * sizeof_long))) )
        {
            end = sizeof_long >= sizeof(end) ? 0 : 1UL << (8 * sizeof_long);
            nr_pages = (end - vend) / (2 * sizeof_long);
            printk("Dom0 memory clipped to %lu pages\n", nr_pages);
        }
    }

    /* Clamp according to available memory (final). */
    nr_pages = min(nr_pages, avail);

    bd->domain->max_pages = min_t(unsigned long, nr_pages, UINT_MAX);

    return nr_pages;
}

void __init arch_create_dom(
    const struct boot_info *bi, struct boot_domain *bd)
{
    static char __initdata cmdline[MAX_GUEST_CMDLINE];

    struct xen_domctl_createdomain dom_cfg = {
        .flags = IS_ENABLED(CONFIG_TBOOT) ? XEN_DOMCTL_CDF_s3_integrity : 0,
        .max_evtchn_port = -1,
        .max_grant_frames = -1,
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
        .max_vcpus = dom_max_vcpus(bd),
        .arch = {
            .misc_flags = bd->functions & BUILD_FUNCTION_INITIAL_DOM &&
                           opt_dom0_msr_relaxed ? XEN_X86_MSR_RELAXED : 0,
        },
    };
    unsigned int is_privileged = 0;

    if ( bd->kernel == NULL )
        panic("Error creating d%uv0\n", bd->domid);

    /* mask out PV and device model bits, if 0 then the domain is PVH */
    if ( !(bd->mode &
           (BUILD_MODE_PARAVIRTUALIZED|BUILD_MODE_ENABLE_DEVICE_MODEL)) )
    {
        dom_cfg.flags |= (XEN_DOMCTL_CDF_hvm |
                         (hvm_hap_supported() ? XEN_DOMCTL_CDF_hap : 0));

        /*
         * If shadow paging is enabled for the initial domain, mask out
         * HAP if it was just enabled.
         */
        if ( builder_is_initdom(bd) )
            if ( opt_dom0_shadow )
                dom_cfg.flags |= ~XEN_DOMCTL_CDF_hap;

        /* TODO: review which flags should be present */
        if ( builder_is_initdom(bd) )
            dom_cfg.arch.emulation_flags |=
                XEN_X86_EMU_LAPIC | XEN_X86_EMU_IOAPIC | XEN_X86_EMU_VPCI;
        else
            dom_cfg.arch.emulation_flags |= X86_EMU_LAPIC;
    }

    if ( iommu_enabled && builder_is_hwdom(bd) )
        dom_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    if ( !pv_shim && builder_is_ctldom(bd) )
        is_privileged = CDF_privileged;

    /* Determine proper domain id. */
    if ( builder_is_initdom(bd) )
        bd->domid = get_initial_domain_id();
    else
        bd->domid = bd->domid ? bd->domid : get_next_domid();
    bd->domain = domain_create(bd->domid, &dom_cfg, is_privileged);
    if ( IS_ERR(bd->domain) )
        panic("Error creating d%u: %ld\n", bd->domid, PTR_ERR(bd->domain));

    if ( builder_is_initdom(bd) )
        init_dom0_cpuid_policy(bd->domain);

    if ( bd->permissions & BUILD_PERMISSION_CONSOLE )
        bd->domain->is_console = true;

    if ( alloc_dom_vcpu0(bd) == NULL )
        panic("Error creating d%uv0\n", bd->domid);

    /* Grab the DOM0 command line. */
    if ( bd->kernel->string.len || boot_info->arch->kextra )
    {
        if ( bd->kernel->string.len )
            safe_strcpy(cmdline, arch_prepare_cmdline(__va(bd->kernel->string.bytes), boot_info->arch));

        if ( builder_is_initdom(bd) )
        {
            if ( bi->arch->kextra )
                /* kextra always includes exactly one leading space. */
                safe_strcat(cmdline, bi->arch->kextra);

            apply_xen_cmdline(cmdline);
        }

        strlcpy(bd->kernel->string.bytes, cmdline, MAX_GUEST_CMDLINE);
    }

    if ( alloc_system_evtchn(bi, bd) != 0 )
        printk(XENLOG_WARNING "%s: "
               "unable set up system event channels for Dom%d\n",
               __func__, bd->domid);

    /*
     * Temporarily clear SMAP in CR4 to allow user-accesses in construct_dom0().
     * This saves a large number of corner cases interactions with
     * copy_from_user().
     */
    if ( cpu_has_smap )
    {
        cr4_pv32_mask &= ~X86_CR4_SMAP;
        write_cr4(read_cr4() & ~X86_CR4_SMAP);
    }

    if ( construct_domain(bd) != 0 )
        panic("Could not construct domain 0\n");

    if ( cpu_has_smap )
    {
        write_cr4(read_cr4() | X86_CR4_SMAP);
        cr4_pv32_mask |= X86_CR4_SMAP;
    }
}

int __init construct_domain(struct boot_domain *bd)
{
    int rc = 0;

    /* Sanity! */
    BUG_ON(bd->domid != bd->domain->domain_id);
    BUG_ON(bd->domain->vcpu[0] == NULL);
    BUG_ON(bd->domain->vcpu[0]->is_initialised);

    process_pending_softirqs();

    if ( is_hvm_domain(bd->domain) )
            rc = dom_construct_pvh(bd);
    else if ( is_pv_domain(bd->domain) )
            rc = dom_construct_pv(bd);
    else
        panic("Cannot construct Dom0. No guest interface available\n");

    if ( rc )
        return rc;

    /* Sanity! */
    BUG_ON(!bd->domain->vcpu[0]->is_initialised);

    return 0;
}
