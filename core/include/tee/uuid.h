/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __TEE_UUID
#define __TEE_UUID

#include <tee_api_types.h>
#include <types_ext.h>

/**
 * tee_uuid_to_octets() - serialize a TEE_UUID into an octet string
 * @dst: pointer to octet string
 * @src: pointer TEE_UUID
 */
void tee_uuid_to_octets(uint8_t *dst, const TEE_UUID *src);

/**
 * tee_uuid_from_octets() - de-serialize an octet string into a TEE_UUID
 * @dst: pointer TEE_UUID
 * @src: pointer to octet string
 */
void tee_uuid_from_octets(TEE_UUID *dst, const uint8_t *src);

/**
 * tee_uuid_from_uint32_t() - de-serialize an uint32_t array into a TEE_UUID
 * An array consisting of 4 <u32> values, The UUID format is described in
 * RFC 4122.
 * @dst: pointer TEE_UUID
 * @src: uint32_t elements
 */
void tee_uuid_from_uint32_t(TEE_UUID *d, uint32_t s0, uint32_t s1, uint32_t s2,
			    uint32_t s3);
#endif /*__TEE_UUID*/
