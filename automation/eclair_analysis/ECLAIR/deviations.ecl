### Set 1 ###

#
# Series 2.
#

-doc_begin="The compiler implementation guarantees that the unreachable code is removed.
Constant expressions and unreachable branches of if and switch statements are expected."
-config=MC3R1.R2.1,+reports={safe,"first_area(^.*has an invariantly.*$)"}
-config=MC3R1.R2.1,+reports={safe,"first_area(^.*incompatible with labeled statement$)"}
-doc_end

-doc_begin="Some functions are intended to be not referenced."
-config=MC3R1.R2.1,+reports={deliberate,"first_area(^.*is never referenced$)"}
-doc_end

-doc_begin="Unreachability caused by calls to the following functions or macros is deliberate and there is no risk of code being unexpectedly left out."
-config=MC3R1.R2.1,statements+={deliberate,"macro(name(BUG||assert_failed))"}
-config=MC3R1.R2.1,statements+={deliberate, "call(decl(name(__builtin_unreachable||panic||do_unexpected_trap||machine_halt||machine_restart||reboot_or_halt)))"}
-doc_end

-doc_begin="Unreachability inside an ASSERT_UNREACHABLE() and analogous macro calls is deliberate and safe."
-config=MC3R1.R2.1,reports+={deliberate, "any_area(any_loc(any_exp(macro(name(ASSERT_UNREACHABLE||PARSE_ERR_RET||PARSE_ERR||FAIL_MSR||FAIL_CPUID)))))"}
-doc_end

-doc_begin="Pure declarations (i.e., declarations without initialization) are
not executable, and therefore it is safe for them to be unreachable."
-config=MC3R1.R2.1,ignored_stmts+={"any()", "pure_decl()"}
-doc_end

+-doc_begin="The following autogenerated file is not linked deliberately."
+-file_tag+={C_runtime_failures,"^automation/eclair_analysis/C-runtime-failures\\.rst\\.c$"}
+-config=MC3R1.R2.1,reports+={deliberate, "any_area(any_loc(file(C_runtime_failures)))"}
+-doc_end

-doc_begin="Proving compliance with respect to Rule 2.2 is generally impossible:
see https://arxiv.org/abs/2212.13933 for details. Moreover, peer review gives us
confidence that no evidence of errors in the program's logic has been missed due
to undetected violations of Rule 2.2, if any. Testing on time behavior gives us
confidence on the fact that, should the program contain dead code that is not
removed by the compiler, the resulting slowdown is negligible."
-config=MC3R1.R2.2,reports+={disapplied,"any()"}
-doc_end

-doc_begin="Some labels are unused in certain build configurations, or are deliberately marked as unused, so that the compiler is entitled to remove them."
-config=MC3R1.R2.6,reports+={deliberate, "any_area(text(^.*__maybe_unused.*$))"}
-doc_end

#
# Series 3.
#

-doc_begin="Comments starting with '/*' and containing hyperlinks are safe as
they are not instances of commented-out code."
-config=MC3R1.R3.1,reports+={safe, "first_area(text(^.*https?://.*$))"}
-doc_end

#
# Series 4.
#

-doc_begin="The directive has been accepted only for the ARM codebase."
-config=MC3R1.D4.3,reports+={disapplied,"!(any_area(any_loc(file(^xen/arch/arm/arm64/.*$))))"}
-doc_end

-doc_begin="This header file is autogenerated or empty, therefore it poses no
risk if included more than once."
-file_tag+={empty_header, "^xen/arch/arm/efi/runtime\\.h$"}
-file_tag+={autogen_headers, "^xen/include/xen/compile\\.h$||^xen/include/generated/autoconf.h$||^xen/include/xen/hypercall-defs.h$"}
-config=MC3R1.D4.10,reports+={safe, "all_area(all_loc(file(empty_header||autogen_headers)))"}
-doc_end

-doc_begin="Files that are intended to be included more than once do not need to
conform to the directive."
-config=MC3R1.D4.10,reports+={safe, "first_area(text(^/\\* This file is legitimately included multiple times\\. \\*/$, begin-4))"}
-config=MC3R1.D4.10,reports+={safe, "first_area(text(^/\\* Generated file, do not edit! \\*/$, begin-3))"}
-doc_end

#
# Series 5.
#

-doc_begin="The project adopted the rule with an exception listed in
'docs/misra/rules.rst'"
-config=MC3R1.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^READ_SYSREG$))&&any_exp(macro(^WRITE_SYSREG$))))"}
-config=MC3R1.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^max(_t)?$))&&any_exp(macro(^min(_t)?$))))"}
-config=MC3R1.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^read[bwlq]$))&&any_exp(macro(^read[bwlq]_relaxed$))))"}
-config=MC3R1.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^per_cpu$))&&any_exp(macro(^this_cpu$))))"}
-config=MC3R1.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^__emulate_2op$))&&any_exp(macro(^__emulate_2op_nobyte$))))"}
-config=MC3R1.R5.3,reports+={safe, "any_area(any_loc(any_exp(macro(^read_debugreg$))&&any_exp(macro(^write_debugreg$))))"}
-doc_end

-doc_begin="The type \"ret_t\" is deliberately defined multiple times,
depending on the guest."
-config=MC3R1.R5.6,reports+={deliberate,"any_area(any_loc(text(^.*ret_t.*$)))"}
-doc_end

-doc_begin="On X86, the types \"guest_intpte_t\", \"guest_l1e_t\" and
\"guest_l2e_t\" are deliberately defined multiple times, depending on the
number of guest paging levels."
-config=MC3R1.R5.6,reports+={deliberate,"any_area(any_loc(file(^xen/arch/x86/include/asm/guest_pt\\.h$)))&&any_area(any_loc(text(^.*(guest_intpte_t|guest_l[12]e_t).*$)))"}
-doc_end

-doc_begin="The following files are imported from the gnu-efi package."
-file_tag+={adopted_r5_6,"^xen/include/efi/.*$"}
-file_tag+={adopted_r5_6,"^xen/arch/.*/include/asm/.*/efibind\\.h$"}
-config=MC3R1.R5.6,reports+={deliberate,"any_area(any_loc(file(adopted_r5_6)))"}
-doc_end

#
# Series 7.
#

-doc_begin="It is safe to use certain octal constants the way they are defined
in specifications, manuals, and algorithm descriptions."
-config=MC3R1.R7.1,reports+={safe, "any_area(any_loc(any_exp(text(^.*octal-ok.*$))))"}
-doc_end

-doc_begin="Violations in files that maintainers have asked to not modify in the
context of R7.2."
-file_tag+={adopted_r7_2,"^xen/include/xen/libfdt/.*$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/include/asm/x86_64/efibind.h$"}
-file_tag+={adopted_r7_2,"^xen/include/efi/efiapi\\.h$"}
-file_tag+={adopted_r7_2,"^xen/include/efi/efidef\\.h$"}
-file_tag+={adopted_r7_2,"^xen/include/efi/efiprot\\.h$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/cpu/intel\\.c$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/cpu/amd\\.c$"}
-file_tag+={adopted_r7_2,"^xen/arch/x86/cpu/common\\.c$"}
-config=MC3R1.R7.2,reports+={deliberate,"any_area(any_loc(file(adopted_r7_2)))"}
-doc_end

-doc_begin="Violations caused by __HYPERVISOR_VIRT_START are related to the
particular use of it done in xen_mk_ulong."
-config=MC3R1.R7.2,reports+={deliberate,"any_area(any_loc(macro(name(BUILD_BUG_ON))))"}
-doc_end

-doc_begin="Allow pointers of non-character type as long as the pointee is
const-qualified."
-config=MC3R1.R7.4,same_pointee=false
-doc_end

#
# Series 8.
#

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_r8_2,"^xen/common/inflate\\.c$"}
-config=MC3R1.R8.2,reports+={deliberate,"any_area(any_loc(file(adopted_r8_2)))"}
-doc_end

-doc_begin="The type ret_t is deliberately used and defined as int or long depending on the architecture."
-config=MC3R1.R8.3,reports+={deliberate,"any_area(any_loc(text(^.*ret_t.*$)))"}
-doc_end

-doc_begin="The following files are imported from Linux and decompress.h defines a unique and documented interface towards all the (adopted) decompress functions."
-file_tag+={adopted_decompress_r8_3,"^xen/common/bunzip2\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unlz4\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unlzma\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unlzo\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unxz\\.c$"}
-file_tag+={adopted_decompress_r8_3,"^xen/common/unzstd\\.c$"}
-config=MC3R1.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_decompress_r8_3)))&&any_area(any_loc(file(^xen/include/xen/decompress\\.h$)))"}
-doc_end

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_time_r8_3,"^xen/arch/x86/time\\.c$"}
-config=MC3R1.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_time_r8_3)))&&(any_area(any_loc(file(^xen/include/xen/time\\.h$)))||any_area(any_loc(file(^xen/arch/x86/include/asm/setup\\.h$))))"}
-doc_end

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_cpu_idle_r8_3,"^xen/arch/x86/acpi/cpu_idle\\.c$"}
-config=MC3R1.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_cpu_idle_r8_3)))&&any_area(any_loc(file(^xen/include/xen/pmstat\\.h$)))"}
-doc_end

-doc_begin="The following file is imported from Linux: ignore for now."
-file_tag+={adopted_mpparse_r8_3,"^xen/arch/x86/mpparse\\.c$"}
-config=MC3R1.R8.3,reports+={deliberate,"any_area(any_loc(file(adopted_mpparse_r8_3)))&&any_area(any_loc(file(^xen/arch/x86/include/asm/mpspec\\.h$)))"}
-doc_end

-doc_begin="The definitions present in this file are meant to generate definitions for asm modules, and are not called by C code. Therefore the absence of prior declarations is safe."
-file_tag+={asm_offsets, "^xen/arch/(arm|x86)/(arm32|arm64|x86_64)/asm-offsets\\.c$"}
-config=MC3R1.R8.4,reports+={safe, "first_area(any_loc(file(asm_offsets)))"}
-doc_end

-doc_begin="The functions defined in this file are meant to be called from gcc-generated code in a non-release build configuration.
Therefore the absence of prior declarations is safe."
-file_tag+={gcov, "^xen/common/coverage/gcov_base\\.c$"}
-config=MC3R1.R8.4,reports+={safe, "first_area(any_loc(file(gcov)))"}
-doc_end

-doc_begin="Recognize the occurrence of current_stack_pointer as a declaration."
-file_tag+={asm_defns, "^xen/arch/x86/include/asm/asm_defns\\.h$"}
-config=MC3R1.R8.4,declarations+={safe, "loc(file(asm_defns))&&^current_stack_pointer$"}
-doc_end

-doc_begin="asmlinkage is a marker to indicate that the function is only used to interface with asm modules."
-config=MC3R1.R8.4,declarations+={safe,"loc(text(^(?s).*asmlinkage.*$, -1..0))"}
-doc_end

-doc_begin="The following variables are compiled in multiple translation units
belonging to different executables and therefore are safe."
-config=MC3R1.R8.6,declarations+={safe, "name(current_stack_pointer||bsearch||sort)"}
-doc_end

-doc_begin="Declarations without definitions are allowed (specifically when the
definition is compiled-out or optimized-out by the compiler)"
-config=MC3R1.R8.6,reports+={deliberate, "first_area(^.*has no definition$)"}
-doc_end

-doc_begin="The search procedure for Unix linkers is well defined, see ld(1)
manual: \"The linker will search an archive only once, at the location where it
is specified on the command line. If the archive defines a symbol which was
undefined in some object which appeared before the archive on the command line,
the linker will include the appropriate file(s) from the archive\".
In Xen, thanks to the order in which file names appear in the build commands,
if arch-specific definitions are present, they get always linked in before
searching in the lib.a archive resulting from xen/lib."
-config=MC3R1.R8.6,declarations+={deliberate, "loc(file(^xen/lib/.*$))"}
-doc_end

-doc_begin="The gnu_inline attribute without static is deliberately allowed."
-config=MC3R1.R8.10,declarations+={deliberate,"property(gnu_inline)"}
-doc_end

#
# Series 9.
#

-doc_begin="Violations in files that maintainers have asked to not modify in the
context of R9.1."
-file_tag+={adopted_r9_1,"^xen/arch/arm/arm64/lib/find_next_bit\\.c$"}
-config=MC3R1.R9.1,reports+={deliberate,"any_area(any_loc(file(adopted_r9_1)))"}
-doc_end

-doc_begin="The possibility of committing mistakes by specifying an explicit
dimension is higher than omitting the dimension."
-config=MC3R1.R9.5,reports+={deliberate, "any()"}
-doc_end

### Set 2 ###

#
# Series 10.
#

-doc_begin="The value-preserving conversions of integer constants are safe"
-config=MC3R1.R10.1,etypes={safe,"any()","preserved_integer_constant()"}
-config=MC3R1.R10.3,etypes={safe,"any()","preserved_integer_constant()"}
-config=MC3R1.R10.4,etypes={safe,"any()","preserved_integer_constant()||sibling(rhs,preserved_integer_constant())"}
-doc_end

-doc_begin="Shifting non-negative integers to the right is safe."
-config=MC3R1.R10.1,etypes+={safe,
  "stmt(node(binary_operator)&&operator(shr))",
  "src_expr(definitely_in(0..))"}
-doc_end

-doc_begin="Shifting non-negative integers to the left is safe if the result is
still non-negative."
-config=MC3R1.R10.1,etypes+={safe,
  "stmt(node(binary_operator)&&operator(shl)&&definitely_in(0..))",
  "src_expr(definitely_in(0..))"}
-doc_end

-doc_begin="Bitwise logical operations on non-negative integers are safe."
-config=MC3R1.R10.1,etypes+={safe,
  "stmt(node(binary_operator)&&operator(and||or||xor))",
  "src_expr(definitely_in(0..))"}
-doc_end

-doc_begin="The implicit conversion to Boolean for logical operator arguments is well known to all Xen developers to be a comparison with 0"
-config=MC3R1.R10.1,etypes+={safe, "stmt(operator(logical)||node(conditional_operator||binary_conditional_operator))", "dst_type(ebool||boolean)"}
-doc_end

-doc_begin="The macro ISOLATE_LSB encapsulates a well-known pattern to obtain
a mask where only the lowest bit set in the argument is set, if any, for unsigned
integers arguments on two's complement architectures
(all the architectures supported by Xen satisfy this requirement)."
-config=MC3R1.R10.1,reports+={safe, "any_area(any_loc(any_exp(macro(^ISOLATE_LSB$))))"}
-doc_end

### Set 3 ###
-doc_begin="XEN only supports architectures where signed integers are
representend using two's complement and all the XEN developers are aware of
this."
-config=MC3R1.R10.1,etypes+={safe,
  "stmt(operator(and||or||xor||not||and_assign||or_assign||xor_assign))",
  "any()"}
-doc_end

-doc_begin="See Section \"4.5 Integers\" of \"GCC_MANUAL\", where it says that
\"Signed `>>' acts on negative numbers by sign extension. As an extension to the
C language, GCC does not use the latitude given in C99 and C11 only to treat
certain aspects of signed `<<' as undefined. However, -fsanitize=shift (and
-fsanitize=undefined) will diagnose such cases. They are also diagnosed where
constant expressions are required.\""
-config=MC3R1.R10.1,etypes+={safe,
  "stmt(operator(shl||shr||shl_assign||shr_assign))",
  "any()"}
-doc_end

#
# Series 11
#

-doc_begin="This construct is used to check if the type is scalar, and for this purpose the use of 0 as a null pointer constant is deliberate."
-config=MC3R1.R11.9,reports+={deliberate, "any_area(any_loc(any_exp(macro(^__ACCESS_ONCE$))))"
}
-doc_end

#
# Series 13
#

-doc_begin="All developers and reviewers can be safely assumed to be well aware
of the short-circuit evaluation strategy of such logical operators."
-config=MC3R1.R13.5,reports+={disapplied,"any()"}
-doc_end

#
# Series 14
#

-doc_begin="The severe restrictions imposed by this rule on the use of for
statements are not balanced by the presumed facilitation of the peer review
activity."
-config=MC3R1.R14.2,reports+={disapplied,"any()"}
-doc_end

-doc_begin="The XEN team relies on the fact that invariant conditions of 'if'
statements are deliberate"
-config=MC3R1.R14.3,statements={deliberate , "wrapped(any(),node(if_stmt))" }
-doc_end

-doc_begin="The XEN team relies on the fact that the enum is_dying has the
constant with assigned value 0 act as false and the other ones as true,
therefore have the same behavior of a boolean"
-config=MC3R1.R14.4,etypes+={deliberate, "stmt(child(cond,child(expr,ref(^<?domain>?::is_dying$))))","src_type(enum)"}
-doc_end

#
# Series 16.
#

-doc_begin="Switch clauses ending with continue, goto, return statements are
safe."
-config=MC3R1.R16.3,terminals+={safe, "node(continue_stmt||goto_stmt||return_stmt)"}
-doc_end

-doc_begin="Switch clauses ending with a call to a function that does not give
the control back (i.e., a function with attribute noreturn) are safe."
-config=MC3R1.R16.3,terminals+={safe, "call(property(noreturn))"}
-doc_end

-doc_begin="Switch clauses ending with pseudo-keyword \"fallthrough\" are
safe."
-config=MC3R1.R16.3,reports+={safe, "any_area(end_loc(any_exp(text(/fallthrough;/))))"}
-doc_end

-doc_begin="Switch clauses ending with failure method \"BUG()\" are safe."
-config=MC3R1.R16.3,reports+={safe, "any_area(end_loc(any_exp(text(/BUG\\(\\);/))))"}
-doc_end

-doc_begin="Switch clauses not ending with the break statement are safe if an
explicit comment indicating the fallthrough intention is present."
-config=MC3R1.R16.3,reports+={safe, "any_area(end_loc(any_exp(text(^(?s).*/\\* [fF]all ?through.? \\*/.*$,0..1))))"}
-doc_end

#
# Series 20.
#

-doc_begin="Code violating Rule 20.7 is safe when macro parameters are used: (1)
as function arguments; (2) as macro arguments; (3) as array indices; (4) as lhs
in assignments."
-config=MC3R1.R20.7,expansion_context=
{safe, "context(__call_expr_arg_contexts)"},
{safe, "context(skip_to(__expr_non_syntactic_contexts, stmt_child(node(array_subscript_expr), subscript)))"},
{safe, "context(skip_to(__expr_non_syntactic_contexts, stmt_child(operator(assign), lhs)))"},
{safe, "left_right(^[(,\\[]$,^[),\\]]$)"}
-doc_end

#
# General
#

-doc_begin="do-while-0 is a well recognized loop idiom by the xen community."
-loop_idioms={do_stmt, "literal(0)"}
-doc_end
-doc_begin="while-[01] is a well recognized loop idiom by the xen community."
-loop_idioms+={while_stmt, "literal(0)||literal(1)"}
-doc_end

#
# Developer confusion
#

-doc="Selection for reports that are fully contained in adopted code."
-report_selector+={adopted_report,"all_area(!kind(culprit||evidence)||all_loc(all_exp(adopted||pseudo)))"}

-doc_begin="Adopted code is not meant to be read, reviewed or modified by human
programmers:no developers' confusion is not possible. In addition, adopted code
is assumed to work as is. Reports that are fully contained in adopted code are
hidden/tagged with the 'adopted' tag."
-service_selector={developer_confusion_guidelines,"^(MC3R1\\.R2\\.1|MC3R1\\.R2\\.2|MC3R1\\.R2\\.3|MC3R1\\.R2\\.4|MC3R1\\.R2\\.5|MC3R1\\.R2\\.6|MC3R1\\.R2\\.7|MC3R1\\.R4\\.1|MC3R1\\.R5\\.3|MC3R1\\.R5\\.6|MC3R1\\.R5\\.7|MC3R1\\.R5\\.8|MC3R1\\.R5\\.9|MC3R1\\.R7\\.1|MC3R1\\.R7\\.2|MC3R1\\.R7\\.3|MC3R1\\.R8\\.7|MC3R1\\.R8\\.8|MC3R1\\.R8\\.9|MC3R1\\.R8\\.11|MC3R1\\.R8\\.12|MC3R1\\.R8\\.13|MC3R1\\.R9\\.3|MC3R1\\.R9\\.4|MC3R1\\.R9\\.5|MC3R1\\.R10\\.2|MC3R1\\.R10\\.5|MC3R1\\.R10\\.6|MC3R1\\.R10\\.7|MC3R1\\.R10\\.8|MC3R1\\.R11\\.9|MC3R1\\.R12\\.1|MC3R1\\.R12\\.3|MC3R1\\.R12\\.4|MC3R1\\.R13\\.5|MC3R1\\.R14\\.1|MC3R1\\.R14\\.2|MC3R1\\.R14\\.3|MC3R1\\.R15\\.1|MC3R1\\.R15\\.2|MC3R1\\.R15\\.3|MC3R1\\.R15\\.4|MC3R1\\.R15\\.5|MC3R1\\.R15\\.6|MC3R1\\.R15\\.7|MC3R1\\.R16\\.1|MC3R1\\.R16\\.2|MC3R1\\.R16\\.3|MC3R1\\.R16\\.4|MC3R1\\.R16\\.5|MC3R1\\.R16\\.6|MC3R1\\.R16\\.7|MC3R1\\.R17\\.7|MC3R1\\.R17\\.8|MC3R1\\.R18\\.4|MC3R1\\.R18\\.5)$"
}
-config=developer_confusion_guidelines,reports+={relied,adopted_report}
-doc_end
