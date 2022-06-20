#ifndef __XEN_BOOTINFO_H__
#define __XEN_BOOTINFO_H__

#include <xen/lib.h>
#include <xen/bootdomain.h>
#include <xen/mm.h>
#include <xen/types.h>
#include <xen/compiler.h>
#include <xen/mm-frame.h>

#if defined CONFIG_X86 || CONFIG_ARM || CONFIG_RISCV
# include <asm/bootinfo.h>
#endif

/* Boot module binary type / purpose */
#define BOOTMOD_UNKNOWN     0
#define BOOTMOD_XEN         1
#define BOOTMOD_FDT         2
#define BOOTMOD_KERNEL      3
#define BOOTMOD_RAMDISK     4
#define BOOTMOD_XSM         5
#define BOOTMOD_UCODE       6
#define BOOTMOD_GUEST_DTB   7
typedef unsigned int bootmod_type_t;

/* Max number of boot modules a bootloader can provide in addition to Xen */
#define MAX_NR_BOOTMODS 63

#define BOOTMOD_STRING_MAX_LEN 1024
struct __packed boot_string {
    char bytes[BOOTMOD_STRING_MAX_LEN];
    size_t len;
};

struct __packed boot_module {
    bootmod_type_t bootmod_type;
    paddr_t start;
    mfn_t mfn;
    size_t size;

    arch_bootmodule_ptr_t arch;
    struct boot_string string;
};
DEFINE_STRUCT_PTR_TYPE(boot_module);

struct __packed boot_info {
    char_ptr_t cmdline;

    unsigned int nr_mods;
    boot_module_ptr_t mods;

    arch_boot_info_ptr_t arch;

    struct domain_builder *builder;
};

extern struct boot_info *boot_info;

static inline char *bootinfo_prepare_cmdline(struct boot_info *bi)
{
    bi->cmdline = arch_bootinfo_prepare_cmdline(bi->cmdline, bi->arch);

    if ( *bi->cmdline == ' ' )
        printk(XENLOG_WARNING "%s: leading whitespace left on cmdline\n",
               __func__);

    return bi->cmdline;
}

static inline unsigned long bootmodule_next_idx_by_type(
    const struct boot_info *bi, bootmod_type_t type, unsigned long start)
{
    for ( ; start < bi->nr_mods; start++ )
        if ( bi->mods[start].bootmod_type == type )
            return start;

    return bi->nr_mods + 1;
}

static inline unsigned long bootmodule_count_by_type(
    const struct boot_info *bi, bootmod_type_t type)
{
    unsigned long count = 0;
    int i;

    for ( i=0; i < bi->nr_mods; i++ )
        if ( bi->mods[i].bootmod_type == type )
            count++;

    return count;
}

static inline struct boot_module *bootmodule_next_by_type(
    const struct boot_info *bi, bootmod_type_t type, unsigned long start)
{
    for ( ; start < bi->nr_mods; start++ )
        if ( bi->mods[start].bootmod_type == type )
            return &bi->mods[start];

    return NULL;
}

static inline struct boot_module *bootmodule_next_by_addr(
    const struct boot_info *bi, paddr_t addr, struct boot_module *start)
{
    /* point end at the entry for xen */
    struct boot_module *end = &bi->mods[bi->nr_mods];

    if ( !start )
        start = bi->mods;

    for ( ; start < end; start++ )
        if ( start->start == addr )
            return start;

    return NULL;
}

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
