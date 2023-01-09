/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 */

#ifndef __TEGRA_DRIVER_FUSE_H__
#define __TEGRA_DRIVER_FUSE_H__

#if defined(PLATFORM_FLAVOR_t194)
#define TEGRA_FUSE_BASE         0x03820000
#define TEGRA_FUSE_SIZE         0x600
#endif

#if defined(PLATFORM_FLAVOR_t234)
#define TEGRA_FUSE_BASE         0x03810000
#define TEGRA_FUSE_SIZE         0x600
#endif

TEE_Result tegra_fuse_map_regs(vaddr_t *va);

#endif
