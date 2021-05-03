/*-
 * Copyright (C) 2010-2015 Daisuke Aoyama <aoyama@peach.ne.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/stdint.h>

#ifndef ISCSI_COMPAT_H
#define ISCSI_COMPAT_H

/* compatible PDU structure */

typedef struct {
	/* 0-3 */
	uint8_t opcode;
	uint8_t opcode_specific1[3];
	/* 4-7 */
	uint8_t total_ahs_len;
	uint8_t data_segment_len[3];
	/* 8-11 */
	union {
		uint8_t lun1[4];
		uint8_t opcode_specific2[4];
	} u1;
	/* 12-15 */
	union {
		uint8_t lun2[4];
		uint8_t opcode_specific3[4];
	} u2;
	/* 16-19 */
	uint8_t inititator_task_tag[4];
	/* 20-47 */
	uint8_t opcode_specific4[28];
} bhs_t;

typedef struct {
	/* 0-3 */
	uint8_t ahs_len[2];
	uint8_t ahs_type;
	uint8_t ahs_specific1;
	/* 4-x */
	uint8_t ahs_specific2[];
} ahs_t;

typedef struct {
	union {
		bhs_t	bhs;
	} ipdu;
	uint32_t	hdr_dig;

	ahs_t		*ahs_addr;
	uint32_t	ahs_len;
	uint32_t	ahs_size;

	uint8_t		*ds_addr;
	uint32_t	ds_len;
	uint32_t	ds_size;
	uint32_t	ds_dig;
} pdu_t;

/* this is cut down version of iscsi_initiator/iscsi.h */

typedef struct opvals {
	int		port;
	int		tags;

	int		maxConnections;
	int		maxRecvDataSegmentLength;
	int		maxXmitDataSegmentLength;
	int		maxBurstLength;
	int		firstBurstLength;
	int		defaultTime2Wait;
	int		defaultTime2Retain;
	int		maxOutstandingR2T;
	int		errorRecoveryLevel;
	int		targetPortalGroupTag;

	boolean_t	initialR2T;
	boolean_t	immediateData;
	boolean_t	dataPDUInOrder;
	boolean_t	dataSequenceInOrder;
	char		*headerDigest;
	char		*dataDigest;
	char		*targetAddress;
	char		*targetName;
	char		*initiatorName;
	char		*authMethod;
} isc_opt_t;

#endif /* ISCSI_COMPAT_H */
