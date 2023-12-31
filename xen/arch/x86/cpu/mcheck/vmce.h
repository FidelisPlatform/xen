#ifndef _MCHECK_VMCE_H
#define _MCHECK_VMCE_H

#include "x86_mca.h"

int vmce_init(struct cpuinfo_x86 *c);

#define dom0_vmce_enabled() \
    (hardware_domain && \
     evtchn_virq_enabled(domain_vcpu(hardware_domain, 0), VIRQ_MCA))

int unmmap_broken_page(struct domain *d, mfn_t mfn, unsigned long gfn);

int vmce_intel_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val);
int vmce_intel_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val);
int vmce_amd_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val);
int vmce_amd_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val);

int fill_vmsr_data(struct mcinfo_bank *mc_bank, struct domain *d,
                   uint64_t gstatus, int vmce_vcpuid);

#define VMCE_INJECT_BROADCAST (-1)
int inject_vmce(struct domain *d, int vcpu);

#endif
