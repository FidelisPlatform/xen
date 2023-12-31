#include "private.h"

#include <xen/lib/x86/cpu-policy.h>

int x86_cpu_policies_are_compatible(const struct cpu_policy *host,
                                    const struct cpu_policy *guest,
                                    struct cpu_policy_errors *err)
{
    struct cpu_policy_errors e = INIT_CPU_POLICY_ERRORS;
    int ret = -EINVAL;

#define NA XEN_CPUID_NO_SUBLEAF
#define FAIL_CPUID(l, s) \
    do { e.leaf = (l); e.subleaf = (s); goto out; } while ( 0 )
#define FAIL_MSR(m) \
    do { e.msr = (m); goto out; } while ( 0 )

    if ( guest->basic.max_leaf > host->basic.max_leaf )
        FAIL_CPUID(0, NA);

    if ( guest->feat.max_subleaf > host->feat.max_subleaf )
        FAIL_CPUID(7, 0);

    if ( guest->extd.max_leaf > host->extd.max_leaf )
        FAIL_CPUID(0x80000000U, NA);

    /* TODO: Audit more CPUID data. */

    if ( ~host->platform_info.raw & guest->platform_info.raw )
        FAIL_MSR(MSR_INTEL_PLATFORM_INFO);

#undef FAIL_MSR
#undef FAIL_CPUID
#undef NA

    /* Success. */
    ret = 0;

 out:
    if ( err )
        *err = e;

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
