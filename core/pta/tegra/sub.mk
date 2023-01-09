srcs-$(CFG_JETSON_USER_KEY_PTA) += jetson_user_key_pta.c

# Add source files and include header files from $(NV_OPTEE_DIR)
ifneq ("$(wildcard $(NV_OPTEE_DIR))","")
subdirs_ext-y += $(NV_OPTEE_DIR)/core/pta/tegra
global-incdirs_ext-y += $(NV_OPTEE_DIR)/lib/libutee/include
endif
