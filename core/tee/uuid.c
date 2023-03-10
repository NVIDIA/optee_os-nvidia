// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <string.h>
#include <tee/uuid.h>
#include <util.h>

void tee_uuid_to_octets(uint8_t *d, const TEE_UUID *s)
{
	d[0] = s->timeLow >> 24;
	d[1] = s->timeLow >> 16;
	d[2] = s->timeLow >> 8;
	d[3] = s->timeLow;
	d[4] = s->timeMid >> 8;
	d[5] = s->timeMid;
	d[6] = s->timeHiAndVersion >> 8;
	d[7] = s->timeHiAndVersion;
	memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

void tee_uuid_from_octets(TEE_UUID *d, const uint8_t *s)
{
	d->timeLow = SHIFT_U32(s[0], 24) | SHIFT_U32(s[1], 16) |
		     SHIFT_U32(s[2], 8) | s[3];
	d->timeMid = SHIFT_U32(s[4], 8) | s[5];
	d->timeHiAndVersion = SHIFT_U32(s[6], 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

void tee_uuid_from_uint32_t(TEE_UUID *d, uint32_t s0, uint32_t s1, uint32_t s2,
			    uint32_t s3)
{
	d->timeLow = s0;
	d->timeMid = s1 >> 16;
	d->timeHiAndVersion = s1 & 0xffff;

	d->clockSeqAndNode[0] = (s2 >> 24) & 0xff;
	d->clockSeqAndNode[1] = (s2 >> 16) & 0xff;
	d->clockSeqAndNode[2] = (s2 >> 8) & 0xff;
	d->clockSeqAndNode[3] = s2 & 0xff;

	d->clockSeqAndNode[4] = (s3 >> 24) & 0xff;
	d->clockSeqAndNode[5] = (s3 >> 16) & 0xff;
	d->clockSeqAndNode[6] = (s3 >> 8) & 0xff;
	d->clockSeqAndNode[7] = s3 & 0xff;
}
