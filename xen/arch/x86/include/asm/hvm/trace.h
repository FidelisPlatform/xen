#ifndef __ASM_X86_HVM_TRACE_H__
#define __ASM_X86_HVM_TRACE_H__

#include <xen/trace.h>

#define DEFAULT_HVM_TRACE_ON  1
#define DEFAULT_HVM_TRACE_OFF 0

#define DEFAULT_HVM_VMSWITCH   DEFAULT_HVM_TRACE_ON
#define DEFAULT_HVM_PF         DEFAULT_HVM_TRACE_ON
#define DEFAULT_HVM_INJECT     DEFAULT_HVM_TRACE_ON
#define DEFAULT_HVM_IO         DEFAULT_HVM_TRACE_ON
#define DEFAULT_HVM_REGACCESS  DEFAULT_HVM_TRACE_ON
#define DEFAULT_HVM_MISC       DEFAULT_HVM_TRACE_ON
#define DEFAULT_HVM_INTR       DEFAULT_HVM_TRACE_ON

#define DO_TRC_HVM_VMENTRY     DEFAULT_HVM_VMSWITCH
#define DO_TRC_HVM_VMEXIT      DEFAULT_HVM_VMSWITCH
#define DO_TRC_HVM_VMEXIT64    DEFAULT_HVM_VMSWITCH
#define DO_TRC_HVM_PF_XEN      DEFAULT_HVM_PF
#define DO_TRC_HVM_PF_XEN64    DEFAULT_HVM_PF
#define DO_TRC_HVM_PF_INJECT   DEFAULT_HVM_PF
#define DO_TRC_HVM_PF_INJECT64 DEFAULT_HVM_PF
#define DO_TRC_HVM_INJ_EXC     DEFAULT_HVM_INJECT
#define DO_TRC_HVM_INJ_VIRQ    DEFAULT_HVM_INJECT
#define DO_TRC_HVM_REINJ_VIRQ  DEFAULT_HVM_INJECT
#define DO_TRC_HVM_INTR_WINDOW DEFAULT_HVM_INJECT
#define DO_TRC_HVM_IO_READ     DEFAULT_HVM_IO
#define DO_TRC_HVM_IO_WRITE    DEFAULT_HVM_IO
#define DO_TRC_HVM_CR_READ     DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_CR_READ64   DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_CR_WRITE    DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_CR_WRITE64  DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_DR_READ     DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_DR_WRITE    DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_XCR_READ64  DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_XCR_WRITE64 DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_MSR_READ    DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_MSR_WRITE   DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_RDTSC       DEFAULT_HVM_REGACCESS
#define DO_TRC_HVM_CPUID       DEFAULT_HVM_MISC
#define DO_TRC_HVM_INTR        DEFAULT_HVM_INTR
#define DO_TRC_HVM_NMI         DEFAULT_HVM_INTR
#define DO_TRC_HVM_MCE         DEFAULT_HVM_INTR
#define DO_TRC_HVM_SMI         DEFAULT_HVM_INTR
#define DO_TRC_HVM_VMMCALL     DEFAULT_HVM_MISC
#define DO_TRC_HVM_HLT         DEFAULT_HVM_MISC
#define DO_TRC_HVM_INVLPG      DEFAULT_HVM_MISC
#define DO_TRC_HVM_INVLPG64    DEFAULT_HVM_MISC
#define DO_TRC_HVM_IO_ASSIST   DEFAULT_HVM_MISC
#define DO_TRC_HVM_MMIO_ASSIST DEFAULT_HVM_MISC
#define DO_TRC_HVM_CLTS        DEFAULT_HVM_MISC
#define DO_TRC_HVM_LMSW        DEFAULT_HVM_MISC
#define DO_TRC_HVM_LMSW64      DEFAULT_HVM_MISC
#define DO_TRC_HVM_REALMODE_EMULATE DEFAULT_HVM_MISC
#define DO_TRC_HVM_TRAP             DEFAULT_HVM_MISC
#define DO_TRC_HVM_TRAP_DEBUG       DEFAULT_HVM_MISC
#define DO_TRC_HVM_VLAPIC           DEFAULT_HVM_MISC


#define TRC_PAR_LONG(par) ((uint32_t)(par)), ((par) >> 32)

#define TRACE_2_LONG_2D(_e, d1, d2, ...) \
    TRACE_4D(_e, d1, d2)
#define TRACE_2_LONG_3D(_e, d1, d2, d3, ...) \
    TRACE_5D(_e, d1, d2, d3)
#define TRACE_2_LONG_4D(_e, d1, d2, d3, d4, ...) \
    TRACE_6D(_e, d1, d2, d3, d4)

#define HVMTRACE_ND(evt, modifier, cycles, ...)                           \
    do {                                                                  \
        if ( unlikely(tb_init_done) && DO_TRC_HVM_ ## evt )               \
        {                                                                 \
            uint32_t _d[] = { __VA_ARGS__ };                              \
            __trace_var(TRC_HVM_ ## evt | (modifier), cycles,             \
                        sizeof(_d), sizeof(_d) ? _d : NULL);              \
        }                                                                 \
    } while(0)

#define HVMTRACE_6D(evt, d1, d2, d3, d4, d5, d6)    \
    HVMTRACE_ND(evt, 0, 0, d1, d2, d3, d4, d5, d6)
#define HVMTRACE_5D(evt, d1, d2, d3, d4, d5)        \
    HVMTRACE_ND(evt, 0, 0, d1, d2, d3, d4, d5)
#define HVMTRACE_4D(evt, d1, d2, d3, d4)            \
    HVMTRACE_ND(evt, 0, 0, d1, d2, d3, d4)
#define HVMTRACE_3D(evt, d1, d2, d3)                \
    HVMTRACE_ND(evt, 0, 0, d1, d2, d3)
#define HVMTRACE_2D(evt, d1, d2)                    \
    HVMTRACE_ND(evt, 0, 0, d1, d2)
#define HVMTRACE_1D(evt, d1)                        \
    HVMTRACE_ND(evt, 0, 0, d1)
#define HVMTRACE_0D(evt)                            \
    HVMTRACE_ND(evt, 0, 0)

#define HVMTRACE_LONG_1D(evt, d1)                  \
                   HVMTRACE_2D(evt ## 64, (uint32_t)(d1), (d1) >> 32)
#define HVMTRACE_LONG_2D(evt, d1, d2, ...)              \
                   HVMTRACE_3D(evt ## 64, d1, d2)
#define HVMTRACE_LONG_3D(evt, d1, d2, d3, ...)      \
                   HVMTRACE_4D(evt ## 64, d1, d2, d3)
#define HVMTRACE_LONG_4D(evt, d1, d2, d3, d4, ...)  \
                   HVMTRACE_5D(evt ## 64, d1, d2, d3, d4)

#endif /* __ASM_X86_HVM_TRACE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
