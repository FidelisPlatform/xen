/*
 * Bridge between MCE and APEI
 *
 * On some machine, corrected memory errors are reported via APEI
 * generic hardware error source (GHES) instead of corrected Machine
 * Check. These corrected memory errors can be reported to user space
 * through /dev/mcelog via faking a corrected Machine Check, so that
 * the error memory page can be offlined by /sbin/mcelog if the error
 * count for one page is beyond the threshold.
 *
 * For fatal MCE, save MCE record into persistent storage via ERST, so
 * that the MCE record can be logged after reboot via ERST.
 *
 * Copyright 2010 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 *   Ported by: Liu, Jinsong <jinsong.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/kernel.h>
#include <xen/cper.h>
#include <xen/errno.h>
#include <acpi/acpi.h>
#include <acpi/apei.h>

#include "mce.h"

#define CPER_CREATOR_MCE						\
	UUID_LE(0x75a574e3U, 0x5052, 0x4b29, 0x8a, 0x8e, 0xbe, 0x2c,	\
		0x64, 0x90, 0xb8, 0x9d)
#define CPER_SECTION_TYPE_MCE						\
	UUID_LE(0xfe08ffbeU, 0x95e4, 0x4be7, 0xbc, 0x73, 0x40, 0x96,	\
		0x04, 0x4a, 0x38, 0xfc)

/*
 * CPER specification (in UEFI specification 2.3 appendix N) requires
 * byte-packed.
 */
struct __packed cper_mce_record {
	struct cper_record_header hdr;
	struct cper_section_descriptor sec_hdr;
	struct mce mce;
};

int apei_write_mce(struct mce *m)
{
	struct cper_mce_record rcd;

	if (!m)
		return -EINVAL;

	memset(&rcd, 0, sizeof(rcd));
	memcpy(rcd.hdr.signature, CPER_SIG_RECORD, CPER_SIG_SIZE);
	rcd.hdr.revision = CPER_RECORD_REV;
	rcd.hdr.signature_end = CPER_SIG_END;
	rcd.hdr.section_count = 1;
	rcd.hdr.error_severity = CPER_SER_FATAL;
	/* timestamp, platform_id, partition_id are all invalid */
	rcd.hdr.validation_bits = 0;
	rcd.hdr.record_length = sizeof(rcd);
	rcd.hdr.creator_id = CPER_CREATOR_MCE;
	rcd.hdr.notification_type = CPER_NOTIFY_MCE;
	rcd.hdr.record_id = cper_next_record_id();
	rcd.hdr.flags = CPER_HW_ERROR_FLAGS_PREVERR;

	rcd.sec_hdr.section_offset = (void *)&rcd.mce - (void *)&rcd;
	rcd.sec_hdr.section_length = sizeof(rcd.mce);
	rcd.sec_hdr.revision = CPER_SEC_REV;
	/* fru_id and fru_text is invalid */
	rcd.sec_hdr.validation_bits = 0;
	rcd.sec_hdr.flags = CPER_SEC_PRIMARY;
	rcd.sec_hdr.section_type = CPER_SECTION_TYPE_MCE;
	rcd.sec_hdr.section_severity = CPER_SER_FATAL;

	memcpy(&rcd.mce, m, sizeof(*m));

	return erst_write(&rcd.hdr);
}

#ifndef NDEBUG /* currently dead code */

ssize_t apei_read_mce(struct mce *m, u64 *record_id)
{
	struct cper_mce_record rcd;
	ssize_t len;

	if (!m || !record_id)
		return -EINVAL;

	len = erst_read_next(&rcd.hdr, sizeof(rcd));
	if (len <= 0)
		return len;
	/* Can not skip other records in storage via ERST unless clear them */
	else if (len != sizeof(rcd) ||
		 uuid_le_cmp(rcd.hdr.creator_id, CPER_CREATOR_MCE)) {
		printk(KERN_WARNING
			"MCE-APEI: Can not skip the unknown record in ERST");
		return -EIO;
	}

	memcpy(m, &rcd.mce, sizeof(*m));
	*record_id = rcd.hdr.record_id;

	return sizeof(*m);
}

/* Check whether there is record in ERST */
bool apei_check_mce(void)
{
	return erst_get_record_count() > 0;
}

int apei_clear_mce(u64 record_id)
{
	return erst_clear(record_id);
}

#endif /* currently dead code */
