/*-
 * Copyright (C) 2010 Daisuke Aoyama <aoyama@peach.ne.jp>
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

#ifndef IBFT_H
#define IBFT_H

#define IBFT_PTOV(addr) ((addr) + KERNBASE)
#define IBFT_VTOP(addr) ((addr) - KERNBASE)

#define IBFT_ALIGN 16
#define IBFT_SIGNATURE "iBFT"
#define IBFT_SIGNATURE_ALT "IBFT"
#define IBFT_SIGNATURE_LENGTH 4
#define IBFT_LOW_ADDR (512*1024)
#define IBFT_HIGH_ADDR (1024*1024)
#define IBFT_IP_LEN 16

#define IBFT_ID_RESERVED	0
#define IBFT_ID_CONTROL		1
#define IBFT_ID_INITIATOR	2
#define IBFT_ID_NIC		3
#define IBFT_ID_TARGET		4
#define IBFT_ID_EXTENSIONS	5

/* word(2byte), dword(4byte) are little endian */
/* word must be on an even byte boundary */
/* strcutre must be on an 8 byte boundary */
/* IP address is stored in IPv6 format */
struct ibft_header {
	/* iBFT Standard Structure Header */
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t index;
	uint8_t flags;
};

/* iBF Table Header 48 bytes */
struct ibft_table_header {
	/* iBF Table Header */
	uint8_t signature[4];
	uint32_t length;
	uint8_t revision;
	uint8_t checksum;
	uint8_t oemid[6];
	uint8_t oemtableid[8];
	uint8_t reserved[24];
};

/* Control Structure 18 bytes(min) */
struct ibft_control {
	/* iBFT Standard Structure Header */
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t index;
	uint8_t flags;

	/* Structure Type Specific */
	uint16_t extensions;
	uint16_t initiator_offset;
	uint16_t nic0_offset;
	uint16_t target0_offset;
	uint16_t nic1_offset;
	uint16_t target1_offset;

	/* Optional Structure Expansion */
	/* ... */
};

/* Initiator Structure 74 bytes */
struct ibft_initiator {
	/* iBFT Standard Structure Header */
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t index;
	uint8_t flags;

	/* Structure Type Specific */
	uint8_t isns[16];
	uint8_t slp[16];
	uint8_t pri_radius[16];
	uint8_t sec_radius[16];
	/* Initiator */
	uint16_t name_length;
	uint16_t name_offset;
};

/* NIC Structure 102 bytes */
struct ibft_nic {
	/* iBFT Standard Structure Header */
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t index;
	uint8_t flags;

	/* Structure Type Specific */
	uint8_t ip[16];
	uint8_t mask_prefix;
	uint8_t origin;
	uint8_t gateway[16];
	uint8_t pri_dns[16];
	uint8_t sec_dns[16];
	uint8_t dhcp[16];
	uint16_t vlan;
	uint8_t mac[6];
	uint16_t pci_bus_dev_func; /* bus=8, dev=5, func=3 bits */
	/* Host */
	uint16_t host_name_length;
	uint16_t host_name_offset;
};

/* Target Structure 54 bytes */
struct ibft_target {
	/* iBFT Standard Structure Header */
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t index;
	uint8_t flags;

	/* Structure Type Specific */
	uint8_t ip[16];
	uint16_t port;
	uint64_t lun;
	uint8_t chap_type;
	uint8_t nic_index;
	/* Target */
	uint16_t name_length;
	uint16_t name_offset;
	/* CHAP */
	uint16_t chap_name_length;
	uint16_t chap_name_offset;
	uint16_t chap_secret_length;
	uint16_t chap_secret_offset;
	/* Reverse CHAP */
	uint16_t rev_chap_name_length;
	uint16_t rev_chap_name_offset;
	uint16_t rev_chap_secret_length;
	uint16_t rev_chap_secret_offset;
};

uint8_t *ibft_get_signature(void);
uint8_t *ibft_get_nic0_mac(void);
struct ibft_initiator *ibft_get_initiator(void);
struct ibft_nic *ibft_get_nic0(void);
struct ibft_target *ibft_get_target0(void);
struct ibft_nic *ibft_get_nic1(void);
struct ibft_target *ibft_get_target1(void);
int ibft_is_zero_address(uint8_t *addr);
void ibft_print_address(uint8_t *addr);
void ibft_print_mac(uint8_t *addr);
int ibft_init(void);

#endif /* IBFT_H */
