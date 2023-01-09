/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 */

#include <config.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <stdlib.h>
#include <tegra_driver_common.h>
#include <tegra_driver_fuse.h>
#include <utee_defines.h>

#ifdef CFG_DT
static const char *const tegra_fuse_dt_match_table[] = {
	"nvidia,tegra194-efuse",
	"nvidia,tegra234-efuse",
};

static TEE_Result tegra_fuse_dt_init(vaddr_t *va)
{
	void *fdt = NULL;
	int node = -1;
	uint32_t i = 0;
	size_t size;

	if (va == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	fdt = get_dt();
	if (!fdt) {
		EMSG("%s: DTB is not present.", __func__);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	for (i = 0; i < ARRAY_SIZE(tegra_fuse_dt_match_table); i++) {
		node = fdt_node_offset_by_compatible(fdt, 0,
						tegra_fuse_dt_match_table[i]);
		if (node >= 0)
			break;
	}

	if (node < 0) {
		EMSG("%s: DT not found (%x).", __func__, node);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (dt_map_dev(fdt, node, va, &size) < 0) {
		EMSG("%s: DT unable to map device address.", __func__);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
#else
static TEE_Result tegra_fuse_dt_init(vaddr_t *va)
{
	(void) va;
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

TEE_Result tegra_fuse_map_regs(vaddr_t *va)
{
	if (IS_ENABLED(CFG_DT))
		return tegra_fuse_dt_init(va);
	else
		return iomap_pa2va(TEGRA_FUSE_BASE, TEGRA_FUSE_SIZE, va);
}
