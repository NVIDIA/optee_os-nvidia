# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020-2022, NVIDIA CORPORATION. All rights reserved.
#

include core/arch/arm/cpu/cortex-armv8-0.mk

# TZDRAM and SHMEM addresses and sizes
CFG_TZDRAM_START ?= 0x80000000

# Use dynamic shared memory and disable static shared memory because
# the NS shared memory address and size are calculated dynamically
$(call force,CFG_CORE_DYN_SHM,y)
$(call force,CFG_CORE_RESERVED_SHM,n)

# The NS memory range may exceed 4GB so 40 bits should be used
CFG_CORE_ARM64_PA_BITS = 40

# Enable ARM64 core
$(call force,CFG_ARM64_core,y)

# Default heap size for Core, 128 kB
CFG_CORE_HEAP_SIZE ?= 131072

# Makes sure everything built is 64-bit, even TA targets.
supported-ta-targets = ta_arm64

# Enables large physical address extension, necessary if ARM64 core is initialized.
$(call force,CFG_WITH_LPAE,y)

# Virtual TEE RAM start address is required for Tegra platforms
ifeq ($(CFG_WITH_LPAE),y)
CFG_LPAE_ADDR_SPACE_BITS = 38
$(call force,CFG_WITH_VIRTUAL_TEE_RAM_START,y)
$(call force,CFG_WITH_PAGER,n)
CFG_EARLY_UART_BASE = 0x0c198000
CFG_EARLY_UART_SIZE = 0x00001000
endif

# Lets platform interact with ATF
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)

# Initialize kernel time source
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)

CFG_DTB_MAX_SIZE = 0x10000
$(call force,CFG_DT,y)
$(call force,CFG_CORE_TPM_EVENT_LOG,n)

# Enable tegra combined UART driver
$(call force,CFG_TEGRA_TCU,y)

$(call force,CFG_RPMB_FS,n)
$(call force,CFG_RPMB_KEY_HAS_PROVISIONED,n)
$(call force,CFG_RPMB_WRITE_KEY,n)
$(call force,CFG_RPMB_TESTKEY,n)

# Enable PKCS11 tests in xtest
$(call force,CFG_PKCS11_TA,y)

# Set the default log level to INFO
$(call force,CFG_TEE_CORE_LOG_LEVEL,2)

# Trusted OS implementation version
# Overriding TEE_IMPL_VERSION for consistency in version reporting
TEE_IMPL_VERSION = $(CFG_OPTEE_REVISION_MAJOR).$(CFG_OPTEE_REVISION_MINOR)

ifeq ($(PLATFORM_FLAVOR),t194)
CFG_TZDRAM_SIZE  ?= 0x00f00000

# T194 has 4 clusters and 2 cores per cluster
$(call force,CFG_CORE_CLUSTER_SHIFT,1)
# Secondary CPU cores. t194 platform contains 8 CPU cores
CFG_TEE_CORE_NB_CORE = 8

# Enable Jetson user key PTA and drivers
$(call force,CFG_JETSON_USER_KEY_PTA,y)
$(call force,CFG_TEGRA_DRIVERS,y)
$(call force,CFG_TEGRA_FUSE,y)
$(call force,CFG_TEGRA_SE,y)
$(call force,CFG_TEGRA_SE_RNG1,y)
ifeq ($(CFG_TEGRA_SE_RNG1),y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
endif

# Enable Early TA support
$(call force,CFG_EARLY_TA,y)
$(call force,CFG_EMBEDDED_TS,y)
endif

ifeq ($(PLATFORM_FLAVOR),t234)
CFG_TZDRAM_SIZE  ?= 0x03fc0000

# T234 has 3 clusters and 4 cores per cluster
$(call force,CFG_CORE_CLUSTER_SHIFT,2)
# Secondary CPU cores. t234 platform contains 12 CPU cores
CFG_TEE_CORE_NB_CORE = 12

# Enable Jetson user key PTA and drivers
$(call force,CFG_JETSON_USER_KEY_PTA,y)
$(call force,CFG_TEGRA_DRIVERS,y)
$(call force,CFG_TEGRA_FUSE,y)
$(call force,CFG_TEGRA_SE,y)
$(call force,CFG_TEGRA_SE_RNG1,y)
ifeq ($(CFG_TEGRA_SE_RNG1),y)
$(call force,CFG_WITH_SOFTWARE_PRNG,n)
endif

# Enable Early TA support
$(call force,CFG_EARLY_TA,y)
$(call force,CFG_EMBEDDED_TS,y)

$(call force,CFG_TEGRA_SE_USE_TEST_KEYS,y)

libdeps += $(NV_CCC_PREBUILT)
endif

# Include platform configs from $(NV_OPTEE_DIR)
ifneq ("$(wildcard $(NV_OPTEE_DIR))","")
include $(NV_OPTEE_DIR)/$(platform-dir)/conf.mk
endif
