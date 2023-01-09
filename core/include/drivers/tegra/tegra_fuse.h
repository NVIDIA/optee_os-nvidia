/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES.
 */

#ifndef __TEGRA_FUSE_H__
#define __TEGRA_FUSE_H__

#include <tee_api_types.h>

typedef struct tegra_fuse_ecid {
	uint32_t ecid[4];
} fuse_ecid_t;

/*
 * Get ECID from fuse
 */
fuse_ecid_t* tegra_fuse_get_ecid(void);

/*
 * Get Boot Security Info from fuse
 */
TEE_Result tegra_fuse_get_bsi(uint32_t *val);

#endif
