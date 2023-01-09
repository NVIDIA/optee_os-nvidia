/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES.
 */

#include <config.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <stdlib.h>
#include <tegra_driver_fuse.h>
#include <tegra_driver_srv_intf.h>
#include <drivers/tegra/tegra_fuse.h>
#include <utee_defines.h>

#define FUSE_OPT_VENDOR_CODE_0		0x200
#define FUSE_OPT_FAB_CODE_0		0x204
#define FUSE_OPT_LOT_CODE_0_0		0x208
#define FUSE_OPT_LOT_CODE_1_0		0x20c
#define FUSE_OPT_WAFER_ID_0		0x210
#define FUSE_OPT_X_COORDINATE_0		0x214
#define FUSE_OPT_Y_COORDINATE_0		0x218
#define FUSE_OPT_OPS_RESERVED_0		0x220
#define OPT_VENDOR_CODE_MASK		0xF
#define OPT_FAB_CODE_MASK		0x3F
#define OPT_LOT_CODE_1_MASK		0xfffffff
#define OPT_WAFER_ID_MASK		0x3F
#define OPT_X_COORDINATE_MASK		0x1FF
#define OPT_Y_COORDINATE_MASK		0x1FF
#define OPT_OPS_RESERVED_MASK		0x3F
#define ECID_ECID0_0_RSVD1_MASK		0x3F
#define ECID_ECID0_0_Y_MASK		0x1FF
#define ECID_ECID0_0_Y_RANGE		6
#define ECID_ECID0_0_X_MASK		0x1FF
#define ECID_ECID0_0_X_RANGE		15
#define ECID_ECID0_0_WAFER_MASK		0x3F
#define ECID_ECID0_0_WAFER_RANGE	24
#define ECID_ECID0_0_LOT1_MASK		0x3
#define ECID_ECID0_0_LOT1_RANGE		30
#define ECID_ECID1_0_LOT1_MASK		0x3FFFFFF
#define ECID_ECID1_0_LOT0_MASK		0x3F
#define ECID_ECID1_0_LOT0_RANGE		26
#define ECID_ECID2_0_LOT0_MASK		0x3FFFFFF
#define ECID_ECID2_0_FAB_MASK		0x3F
#define ECID_ECID2_0_FAB_RANGE		26
#define ECID_ECID3_0_VENDOR_MASK	0xF

static vaddr_t fuse_va_base = 0;
static fuse_ecid_t fuse_ecid;

static TEE_Result fuse_get_bsi(uint32_t *val)
{
	(void) val;
	return TEE_ERROR_NOT_SUPPORTED;
}

static fuse_ecid_t* fuse_get_queried_ecid(void)
{
	return &fuse_ecid;
}

static void fuse_query_ecid(void)
{
	uint32_t vendor, fab, wafer;
	uint32_t lot0, lot1;
	uint32_t x, y;
	uint32_t rsvd1;
	uint32_t reg;

	if (fuse_va_base == 0)
		return;

	reg = io_read32(fuse_va_base + FUSE_OPT_VENDOR_CODE_0);
	vendor = reg & OPT_VENDOR_CODE_MASK;

	reg = io_read32(fuse_va_base + FUSE_OPT_FAB_CODE_0);
	fab = reg & OPT_FAB_CODE_MASK;

	lot0 = io_read32(fuse_va_base + FUSE_OPT_LOT_CODE_0_0);

	lot1 = 0;
	reg = io_read32(fuse_va_base + FUSE_OPT_LOT_CODE_1_0);
	lot1 = reg & OPT_LOT_CODE_1_MASK;

	reg = io_read32(fuse_va_base + FUSE_OPT_WAFER_ID_0);
	wafer = reg & OPT_WAFER_ID_MASK;

	reg = io_read32(fuse_va_base + FUSE_OPT_X_COORDINATE_0);
	x = reg & OPT_X_COORDINATE_MASK;

	reg = io_read32(fuse_va_base + FUSE_OPT_Y_COORDINATE_0);
	y = reg & OPT_Y_COORDINATE_MASK;

	reg = io_read32(fuse_va_base + FUSE_OPT_OPS_RESERVED_0);
	rsvd1 = reg & OPT_OPS_RESERVED_MASK;

	reg = 0;
	reg |= rsvd1 && ECID_ECID0_0_RSVD1_MASK;
	reg |= (y & ECID_ECID0_0_Y_MASK) << ECID_ECID0_0_Y_RANGE;
	reg |= (x & ECID_ECID0_0_X_MASK) << ECID_ECID0_0_X_RANGE;
	reg |= (wafer & ECID_ECID0_0_WAFER_MASK) << ECID_ECID0_0_WAFER_RANGE;
	reg |= (lot1 & ECID_ECID0_0_LOT1_MASK) << ECID_ECID0_0_LOT1_RANGE;
	fuse_ecid.ecid[0] = reg;

	lot1 >>= 2;

	reg = 0;
	reg |= lot1 & ECID_ECID1_0_LOT1_MASK;
	reg |= (lot0 & ECID_ECID1_0_LOT0_MASK) << ECID_ECID1_0_LOT0_RANGE;
	fuse_ecid.ecid[1] = reg;

	lot0 >>= 6;

	reg = 0;
	reg |= lot0 & ECID_ECID2_0_LOT0_MASK;
	reg |= (fab & ECID_ECID2_0_FAB_MASK) << ECID_ECID2_0_FAB_RANGE;
	fuse_ecid.ecid[2] = reg;

	reg = 0;
	reg |= vendor & ECID_ECID3_0_VENDOR_MASK;
	fuse_ecid.ecid[3] = reg;
}

static TEE_Result tegra_fuse_init(void)
{
	TEE_Result rc = TEE_SUCCESS;

	rc = tegra_fuse_map_regs(&fuse_va_base);

	if (rc == TEE_SUCCESS) {
		tegra_drv_srv_intf_t *drv_srv_intf;

		fuse_query_ecid();
		drv_srv_intf = tegra_drv_srv_intf_get();

		if (drv_srv_intf != NULL) {
			drv_srv_intf->get_ecid = fuse_get_queried_ecid;
			drv_srv_intf->get_bsi = fuse_get_bsi;
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
	}

        return rc;
}

service_init(tegra_fuse_init);
