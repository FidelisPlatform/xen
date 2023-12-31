/*
 * apei-internal.h - ACPI Platform Error Interface internal
 * definations.
 */

#ifndef APEI_INTERNAL_H
#define APEI_INTERNAL_H

struct apei_exec_context;

typedef int (*apei_exec_ins_func_t)(struct apei_exec_context *ctx,
				    struct acpi_whea_header *entry);

#define APEI_EXEC_INS_ACCESS_REGISTER	0x0001

struct apei_exec_ins_type {
	u32 flags;
	apei_exec_ins_func_t run;
};

struct apei_exec_context {
	u32 ip;
	u64 value;
	u64 var1;
	u64 var2;
	u64 src_base;
	u64 dst_base;
	struct apei_exec_ins_type *ins_table;
	u32 instructions;
	struct acpi_whea_header *action_table;
	u32 entries;
};

int apei_exec_ctx_init(struct apei_exec_context *ctx,
			struct apei_exec_ins_type *ins_table,
			u32 instructions,
			struct acpi_whea_header *action_table,
			u32 entries);

static inline void apei_exec_ctx_set_input(struct apei_exec_context *ctx,
					   u64 input)
{
	ctx->value = input;
}

static inline u64 apei_exec_ctx_get_output(struct apei_exec_context *ctx)
{
	return ctx->value;
}

int __apei_exec_run(struct apei_exec_context *ctx, u8 action, bool optional);

static inline int apei_exec_run(struct apei_exec_context *ctx, u8 action)
{
	return __apei_exec_run(ctx, action, 0);
}

/* It is optional whether the firmware provides the action */
static inline int apei_exec_run_optional(struct apei_exec_context *ctx, u8 action)
{
	return __apei_exec_run(ctx, action, 1);
}

/* Common instruction implementation */

/* IP has been set in instruction function */
#define APEI_EXEC_SET_IP	1

int __apei_exec_read_register(struct acpi_whea_header *entry, u64 *val);
int __apei_exec_write_register(struct acpi_whea_header *entry, u64 val);
int cf_check apei_exec_read_register(
	struct apei_exec_context *ctx, struct acpi_whea_header *entry);
int cf_check apei_exec_read_register_value(
	struct apei_exec_context *ctx, struct acpi_whea_header *entry);
int cf_check apei_exec_write_register(
	struct apei_exec_context *ctx, struct acpi_whea_header *entry);
int cf_check apei_exec_write_register_value(
	struct apei_exec_context *ctx, struct acpi_whea_header *entry);
int cf_check apei_exec_noop(
	struct apei_exec_context *ctx, struct acpi_whea_header *entry);
int apei_exec_pre_map_gars(struct apei_exec_context *ctx);
int apei_exec_post_unmap_gars(struct apei_exec_context *ctx);

#endif
