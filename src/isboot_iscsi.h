/*-
 * Copyright (c) 2025 John Nielsen <john@jnielsen.net>
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

#ifndef ISBOOT_ISCSI_H
#define ISBOOT_ISCSI_H

#define ISBOOT_SOCK_TIMEOUT 30
#define ISBOOT_CAM_TAGS 32
#define ISBOOT_CAM_MAX_TAGS 255
#define ISBOOT_CHAP_CHALLENGE_LEN 1024
#define ISBOOT_CHAP_CHALLENGE_STRLEN (3 + (ISBOOT_CHAP_CHALLENGE_LEN * 2))
#define ISBOOT_CHAP_MAX_DIGEST_LEN 16
#define ISBOOT_CHAP_MAX_DIGEST_STRLEN (3 + (ISBOOT_CHAP_MAX_DIGEST_LEN * 2))
#define ISBOOT_CHAP_MAX_USER_LEN (ISBOOT_NAME_MAX)

#define ISBOOT_NO_STAGE -1
#define ISBOOT_SECURITYNEGOTIATION 0
#define ISBOOT_LOGINOPERATIONALNEGOTIATION 1
#define ISBOOT_FULLFEATUREPHASE 3

#define ISBOOT_CHAP_NONE 0
#define ISBOOT_CHAP_WAIT_A 1
#define ISBOOT_CHAP_WAIT_NR 2
#define ISBOOT_CHAP_MUTUAL 3
#define ISBOOT_CHAP_END 4

#define ISBOOT_ERROR(...) do { printf(__VA_ARGS__); } while (0)

#define ISBOOT_LVL_WARN 1
#define ISBOOT_LVL_INFO 2
#define ISBOOT_LVL_DEBUG 3
#define ISBOOT_TRACE(lvl, ...) do { if(isboot_trace_level >= lvl) printf(__VA_ARGS__); } while (0)
#define ISBOOT_PRINT(...) do { printf("isboot0: "); printf(__VA_ARGS__); } while (0)

/* iscsi_initiator.ko handling based on iscsi-2.2.4 by Daniel Braniss */
/* and based on istgt-20100606 by Daisuke Aoyama */

#define ISCSI_BHS_LEN 48
#define ISCSI_ALIGNMENT 4
#define ISCSI_ALIGN(SIZE) \
        (((SIZE) + (ISCSI_ALIGNMENT - 1)) & ~(ISCSI_ALIGNMENT - 1))

/* RFC3720 10.2.1.2 */
#define	ISCSI_OP_NOP_OUT	0x00
#define	ISCSI_OP_SCSI_CMD	0x01
#define	ISCSI_OP_TASK_REQ	0x02
#define	ISCSI_OP_LOGIN_REQ	0x03
#define	ISCSI_OP_TEXT_REQ	0x04
#define	ISCSI_OP_WRITE_DATA	0x05
#define	ISCSI_OP_LOGOUT_REQ	0x06
#define	ISCSI_OP_SNACK		0x10

#define	ISCSI_OP_NOP_IN		0x20
#define	ISCSI_OP_SCSI_RSP	0x21
#define	ISCSI_OP_TASK_RSP	0x22
#define	ISCSI_OP_LOGIN_RSP	0x23
#define	ISCSI_OP_TEXT_RSP	0x24
#define	ISCSI_OP_READ_DATA	0x25
#define	ISCSI_OP_LOGOUT_RSP	0x26
#define	ISCSI_OP_R2T		0x31
#define	ISCSI_OP_ASYNC_MSG	0x32
#define	ISCSI_OP_REJECT		0x3f

/* RFC3720 10.3.1 */
#define	ISCSI_TASK_ATTR_UNTAGGED	0
#define	ISCSI_TASK_ATTR_SIMPLE		1
#define	ISCSI_TASK_ATTR_ORDERED		2
#define	ISCSI_TASK_ATTR_HOQ		3
#define	ISCSI_TASK_ATTR_ACA		4

/* network byte and bit manipulator from istgt */
#define DSET8(B,D)	(*((uint8_t *)(B)) = (uint8_t)(D))
#define DSET16(B,D)							\
        (   ((*((uint8_t *)(B)+0)) = (uint8_t)((uint16_t)(D) >> 8)),	\
	    ((*((uint8_t *)(B)+1)) = (uint8_t)((uint16_t)(D) >> 0)))
#define DSET24(B,D)							\
	(   ((*((uint8_t *)(B)+0)) = (uint8_t)((uint32_t)(D) >> 16)),	\
	    ((*((uint8_t *)(B)+1)) = (uint8_t)((uint32_t)(D) >> 8)),	\
	    ((*((uint8_t *)(B)+2)) = (uint8_t)((uint32_t)(D) >> 0)))
#define DSET32(B,D)							\
        (   ((*((uint8_t *)(B)+0)) = (uint8_t)((uint32_t)(D) >> 24)),	\
	    ((*((uint8_t *)(B)+1)) = (uint8_t)((uint32_t)(D) >> 16)),	\
	    ((*((uint8_t *)(B)+2)) = (uint8_t)((uint32_t)(D) >> 8)),	\
	    ((*((uint8_t *)(B)+3)) = (uint8_t)((uint32_t)(D) >> 0)))
#define DSET48(B,D)							\
        (   ((*((uint8_t *)(B)+0)) = (uint8_t)((uint64_t)(D) >> 40)),	\
	    ((*((uint8_t *)(B)+1)) = (uint8_t)((uint64_t)(D) >> 32)),	\
	    ((*((uint8_t *)(B)+2)) = (uint8_t)((uint64_t)(D) >> 24)),	\
	    ((*((uint8_t *)(B)+3)) = (uint8_t)((uint64_t)(D) >> 16)),	\
	    ((*((uint8_t *)(B)+4)) = (uint8_t)((uint64_t)(D) >> 8)),	\
	    ((*((uint8_t *)(B)+5)) = (uint8_t)((uint64_t)(D) >> 0)))
#define DSET64(B,D)							\
	(   ((*((uint8_t *)(B)+0)) = (uint8_t)((uint64_t)(D) >> 56)),	\
	    ((*((uint8_t *)(B)+1)) = (uint8_t)((uint64_t)(D) >> 48)),	\
	    ((*((uint8_t *)(B)+2)) = (uint8_t)((uint64_t)(D) >> 40)),	\
	    ((*((uint8_t *)(B)+3)) = (uint8_t)((uint64_t)(D) >> 32)),	\
	    ((*((uint8_t *)(B)+4)) = (uint8_t)((uint64_t)(D) >> 24)),	\
	    ((*((uint8_t *)(B)+5)) = (uint8_t)((uint64_t)(D) >> 16)),	\
	    ((*((uint8_t *)(B)+6)) = (uint8_t)((uint64_t)(D) >> 8)),	\
	    ((*((uint8_t *)(B)+7)) = (uint8_t)((uint64_t)(D) >> 0)))
#define DGET8(B)	(*((uint8_t *)(B)))
#define DGET16(B)							\
        (     (((uint16_t) *((uint8_t *)(B)+0)) << 8)			\
	    | (((uint16_t) *((uint8_t *)(B)+1)) << 0))
#define DGET24(B)							\
        (     (((uint32_t) *((uint8_t *)(B)+0)) << 16)			\
	    | (((uint32_t) *((uint8_t *)(B)+1)) << 8)			\
	    | (((uint32_t) *((uint8_t *)(B)+2)) << 0))
#define DGET32(B)							\
        (     (((uint32_t) *((uint8_t *)(B)+0)) << 24)			\
	    | (((uint32_t) *((uint8_t *)(B)+1)) << 16)			\
	    | (((uint32_t) *((uint8_t *)(B)+2)) << 8)			\
	    | (((uint32_t) *((uint8_t *)(B)+3)) << 0))
#define DGET48(B)							\
        (     (((uint64_t) *((uint8_t *)(B)+0)) << 40)			\
	    | (((uint64_t) *((uint8_t *)(B)+1)) << 32)			\
	    | (((uint64_t) *((uint8_t *)(B)+2)) << 24)			\
	    | (((uint64_t) *((uint8_t *)(B)+3)) << 16)			\
	    | (((uint64_t) *((uint8_t *)(B)+4)) << 8)			\
	    | (((uint64_t) *((uint8_t *)(B)+5)) << 0))
#define DGET64(B)							\
        (     (((uint64_t) *((uint8_t *)(B)+0)) << 56)			\
	    | (((uint64_t) *((uint8_t *)(B)+1)) << 48)			\
	    | (((uint64_t) *((uint8_t *)(B)+2)) << 40)			\
	    | (((uint64_t) *((uint8_t *)(B)+3)) << 32)			\
	    | (((uint64_t) *((uint8_t *)(B)+4)) << 24)			\
	    | (((uint64_t) *((uint8_t *)(B)+5)) << 16)			\
	    | (((uint64_t) *((uint8_t *)(B)+6)) << 8)			\
	    | (((uint64_t) *((uint8_t *)(B)+7)) << 0))
/* B=buffer, D=data, N=bit, W=width of bits */
#define BSHIFTNW(N,W) \
	(((W) > 0) ? (((N) > ((W)-1)) ? ((N) - ((W)-1)) : 0) : 0)
#define BMASKW(W) (((W) > 0) ? (~((~0U) << (W))) : 0)
#define BDSET8W(B,D,N,W) DSET8((B),(((D)&BMASKW((W)))<<BSHIFTNW((N),(W))))
#define BDADD8W(B,D,N,W) \
	DSET8((B),((DGET8((B)) & ~(BMASKW((W)) << BSHIFTNW((N),(W)))) | (uint8_t) (((D) & BMASKW((W))) << BSHIFTNW((N),(W)))))
#define BSET8W(B,N,W) \
	(*((uint8_t *)(B)) |= (uint8_t) (BMASKW((W))) << BSHIFTNW((N),(W)))
#define BCLR8W(B,N,W) \
	(*((uint8_t *)(B)) &= (uint8_t) (~(BMASKW((W))) << BSHIFTNW((N),(W))))
#define BGET8W(B,N,W) ((*((uint8_t *)(B)) >> BSHIFTNW((N),(W))) & BMASKW((W)))

#define BDSET8(B,D,N) (BDSET8W((B),(D),(N),1))
#define BDADD8(B,D,N) (BDADD8W((B),(D),(N),1))
#define BSET8(B,N) (BSET8W((B),(N),1))
#define BCLR8(B,N) (BCLR8W((B),(N),1))
#define BGET8(B,N) (BGET8W((B),(N),1))

#define MATCH_DIGEST_WORD(BUF, CRC32C)				\
	((    (((uint32_t) *((uint8_t *)(BUF)+0)) << 0)		\
	    | (((uint32_t) *((uint8_t *)(BUF)+1)) << 8)         \
	    | (((uint32_t) *((uint8_t *)(BUF)+2)) << 16)        \
	    | (((uint32_t) *((uint8_t *)(BUF)+3)) << 24))       \
	    == (CRC32C))
#define MAKE_DIGEST_WORD(BUF, CRC32C)					\
        (   ((*((uint8_t *)(BUF)+0)) = (uint8_t)((uint32_t)(CRC32C) >> 0)), \
	    ((*((uint8_t *)(BUF)+1)) = (uint8_t)((uint32_t)(CRC32C) >> 8)), \
	    ((*((uint8_t *)(BUF)+2)) = (uint8_t)((uint32_t)(CRC32C) >> 16)), \
	    ((*((uint8_t *)(BUF)+3)) = (uint8_t)((uint32_t)(CRC32C) >> 24)))

#endif /* ISBOOT_ISCSI_H */
