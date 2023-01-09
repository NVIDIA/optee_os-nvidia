incdirs-y += include
incdirs-y += ../common/include

srcs-$(CFG_TEGRA_FUSE) += fuse.c
srcs-$(CFG_TEGRA_SE) += tegra_se_aes.c
srcs-$(CFG_TEGRA_SE) += tegra_se_mgnt.c
srcs-$(CFG_TEGRA_SE_RNG1) += tegra_se_rng1.c
