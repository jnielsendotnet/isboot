/*-
 * Copyright (C) 2010-2011 Daisuke Aoyama <aoyama@peach.ne.jp>
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/vmparam.h>
#include <contrib/dev/acpica/include/acpi.h>
#include "opt_acpi.h"
#include "ibft.h"

/* location of iBFT */
uint8_t *ibft_signature = NULL;

/* offset from iBFT */
int ibft_initiator_offset = 0;
int ibft_nic0_offset = 0;
int ibft_target0_offset = 0;
int ibft_nic1_offset = 0;
int ibft_target1_offset = 0;

/* flags */
#ifdef IBFT_VERBOSE
int ibft_verbose = 1;
#else
int ibft_verbose = 0;
#endif

uint8_t *
ibft_get_signature(void)
{

	return (ibft_signature);
}

uint8_t *
ibft_get_nic0_mac(void)
{

	if (ibft_signature == NULL)
		return (NULL);
	if (ibft_nic0_offset == 0)
		return (NULL);
	return ((struct ibft_nic *)(ibft_signature + ibft_nic0_offset))->mac;
}

struct ibft_initiator *
ibft_get_initiator(void)
{

	if (ibft_signature == NULL)
		return (NULL);
	return (struct ibft_initiator *)(ibft_signature +
	    ibft_initiator_offset);
}

struct ibft_nic *
ibft_get_nic0(void)
{

	if (ibft_signature == NULL)
		return (NULL);
	if (ibft_nic0_offset == 0)
		return (NULL);
	return (struct ibft_nic *)(ibft_signature + ibft_nic0_offset);
}

struct ibft_target *
ibft_get_target0(void)
{

	if (ibft_signature == NULL)
		return (NULL);
	if (ibft_target0_offset == 0)
		return (NULL);
	return (struct ibft_target *)(ibft_signature + ibft_target0_offset);
}

struct ibft_nic *
ibft_get_nic1(void)
{

	if (ibft_signature == NULL)
		return (NULL);
	if (ibft_nic1_offset == 0)
		return (NULL);
	return (struct ibft_nic *)(ibft_signature + ibft_nic1_offset);
}

struct ibft_target *
ibft_get_target1(void)
{

	if (ibft_signature == NULL)
		return (NULL);
	if (ibft_target1_offset == 0)
		return (NULL);
	return (struct ibft_target *)(ibft_signature + ibft_target1_offset);
}

int
ibft_is_zero_address(uint8_t *addr)
{
	uint32_t n0, n1, n2, n3;

	/* all zeros means "not present" or "not specified" in iBFT */
	n0 = be32toh(*(uint32_t *)(addr + 0));
	n1 = be32toh(*(uint32_t *)(addr + 4));
	n2 = be32toh(*(uint32_t *)(addr + 8));
	n3 = be32toh(*(uint32_t *)(addr +12));
	if (n0 == 0 && n1 == 0 && n2 == 0 && n3 == 0)
		return (1);
	return (0);
}

void
ibft_print_address(uint8_t *addr)
{
	uint32_t n0, n1, n2;

	/* RFC2373 2.5.4 */
	n0 = be32toh(*(uint32_t *)(addr + 0));
	n1 = be32toh(*(uint32_t *)(addr + 4));
	n2 = be32toh(*(uint32_t *)(addr + 8));
	if (n0 == 0 && n1 == 0 && n2 == 0x0000ffffU) {
		/* IPv4-mapped IPv6 */
		printf("%d.%d.%d.%d",
		    addr[12], addr[13], addr[14], addr[15]);
	} else {
		/* IPv6 */
		printf("%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x",
		    addr[0], addr[1], addr[2], addr[3],
		    addr[4], addr[5], addr[6], addr[7],
		    addr[8], addr[9], addr[10], addr[11],
		    addr[12], addr[13], addr[14], addr[15]);
	}
}

void
ibft_print_mac(uint8_t *addr)
{

	printf("%02x:%02x:%02x:%02x:%02x:%02x",
	    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/* verify iBFT checksum and retrieve offsets of initiator, NICs, targets */
static int
ibft_parse_structure(uint8_t *ibft)
{
	struct ibft_table_header *th;
	struct ibft_control *ch;
	struct ibft_initiator *ih;
	struct ibft_nic *n0h, *n1h;
	struct ibft_target *t0h, *t1h;
	char oemid[6+1], oemtableid[8+1];
	int id, length, index, flags;
	int revision, checksum;
	int name_length, name_offset;
	int sum, i;

	/* iBF Table Header (48 bytes) */
	th = (struct ibft_table_header *)ibft;
	length = le32toh(th->length);
	revision = th->revision;
	checksum = th->checksum;
	memcpy(oemid, th->oemid, 6);
	oemid[6] = '\0';
	memcpy(oemtableid, th->oemtableid, 8);
	oemtableid[8] = '\0';
	if (ibft_verbose) {
		printf("iBFT: length=%d, revision=%d, checksum=0x%x\n",
		    length, revision, checksum);
		printf("iBFT: oemid='%s', oemtableid='%s'\n",
		    oemid, oemtableid);
	}

	/* verify checksum of iBFT */
	sum = 0;
	for (i = 0; i < length; i++) {
		sum += *((uint8_t *)ibft + i);
	}
	sum &= 0xffU;
	if (ibft_verbose) {
		printf("iBFT: sum = 0x%x\n", sum);
	}
	if (sum != 0) {
		printf("iBFT: checksum error sum=0x%x\n", sum);
		return (-1);
	}

	/* Control Structure (18 bytes or more) */
	ch = (struct ibft_control *)(ibft + 48);
	id = ch->id;
	length = le16toh(ch->length);
	index = ch->index;
	flags = ch->flags;
	if (id != IBFT_ID_CONTROL) {
		printf("iBFT: Control Structure error (id=%d)\n", id);
		return (-1);
	}

	/* save offsets for quick access */
	ibft_initiator_offset = ch->initiator_offset;
	ibft_nic0_offset = ch->nic0_offset;
	ibft_target0_offset = ch->target0_offset;
	ibft_nic1_offset = ch->nic1_offset;
	ibft_target1_offset = ch->target1_offset;
	if (length > 18) {
		/* XXX optional */
	}
	if (ibft_verbose) {
		printf("iBFT: CS: length=%d, index=%d, flags=0x%x\n",
		    length, index, flags);
		printf("iBFT: CS: initiator=%d, nic0=%d, target0=%d, "
		    "nic1=%d, target1=%d\n",
		    ibft_initiator_offset,
		    ibft_nic0_offset, ibft_target0_offset,
		    ibft_nic1_offset, ibft_target1_offset);
	}

	/* Initiator Structure */
	if (ibft_initiator_offset != 0) {
		ih = (struct ibft_initiator *)(ibft + ibft_initiator_offset);
		id = ih->id;
		length = le16toh(ih->length);
		index = ih->index;
		flags = ih->flags;
		if (id != IBFT_ID_INITIATOR) {
			printf("iBFT: Initiator Structure error (id=%d)\n",
			    id);
			return (-1);
		}
		if (ibft_verbose) {
			printf("iBFT: IS: length=%d, index=%d, flags=0x%x\n",
			    length, index, flags);
		}
		if (ibft_verbose) {
			if (!ibft_is_zero_address(ih->isns)) {
				printf("iSNS Server:\n");
				ibft_print_address(ih->isns);
				printf("\n");
			}
			if (!ibft_is_zero_address(ih->slp)) {
				printf("SLP Server:\n");
				ibft_print_address(ih->slp);
				printf("\n");
			}
			if (!ibft_is_zero_address(ih->pri_radius)) {
				printf("Primary Radius Server:\n");
				ibft_print_address(ih->pri_radius);
				printf("\n");
			}
			if (!ibft_is_zero_address(ih->sec_radius)) {
				printf("Secondary Radius Server:\n");
				ibft_print_address(ih->sec_radius);
				printf("\n");
			}
		}

		name_length = ih->name_length;
		name_offset = ih->name_offset;
		if (name_offset != 0) {
			printf("IS: ");
			printf("Initiator name: ");
			printf("%.*s\n", name_length, (ibft + name_offset));
		}
	}

	/* NIC0 Structure */
	if (ibft_nic0_offset != 0) {
		n0h = (struct ibft_nic *)(ibft + ibft_nic0_offset);
		id = n0h->id;
		length = le16toh(n0h->length);
		index = n0h->index;
		flags = n0h->flags;
		if (id != IBFT_ID_NIC) {
			printf("iBFT: NIC0 Structure error (id=%d)\n", id);
			return (-1);
		}
		if (ibft_verbose) {
			printf("iBFT: NIC0: length=%d, index=%d, "
			    "flags=0x%x\n",
			    length, index, flags);
		}

		printf("NIC0: ");
		printf("IP address: ");
		ibft_print_address(n0h->ip);
		printf("\n");
		printf("NIC0: ");
		printf("Prefix: ");
		printf("%d\n", n0h->mask_prefix);

		if (ibft_verbose) {
			printf("NIC0: ");
			printf("Origin: ");
			printf("%d\n", n0h->origin);
		}

		if (!ibft_is_zero_address(n0h->gateway)) {
			printf("NIC0: ");
			printf("Gateway: ");
			ibft_print_address(n0h->gateway);
			printf("\n");
		}

		if (ibft_verbose) {
			if (!ibft_is_zero_address(n0h->pri_dns)) {
				printf("NIC0: ");
				printf("Primary DNS: ");
				ibft_print_address(n0h->pri_dns);
				printf("\n");
			}
			if (!ibft_is_zero_address(n0h->sec_dns)) {
				printf("NIC0: ");
				printf("Secondary DNS: ");
				ibft_print_address(n0h->sec_dns);
				printf("\n");
			}
			if (!ibft_is_zero_address(n0h->dhcp)) {
				printf("NIC0: ");
				printf("DHCP: ");
				ibft_print_address(n0h->dhcp);
				printf("\n");
			}

			printf("NIC0: ");
			printf("VLAN: ");
			printf("%d\n", le16toh(n0h->vlan));
		}

		printf("NIC0: ");
		printf("MAC address: ");
		ibft_print_mac(n0h->mac);
		printf("\n");

		if (ibft_verbose) {
			printf("NIC0: ");
			printf("PCI Bus/Dev/Func: ");
			printf("%x (%x/%x/%x)\n",
			    le16toh(n0h->pci_bus_dev_func),
			    (le16toh(n0h->pci_bus_dev_func) >> 8) & 0x00ffU,
			    (le16toh(n0h->pci_bus_dev_func) >> 3) & 0x001fU,
			    (le16toh(n0h->pci_bus_dev_func) & 0x0003U));
		}

		name_length = n0h->host_name_length;
		name_offset = n0h->host_name_offset;
		if (name_offset != 0) {
			printf("NIC0: ");
			printf("Host name: ");
			printf("%.*s\n", name_length, (ibft + name_offset));
			printf("\n");
		}
	}

	/* Target0 Structure */
	if (ibft_target0_offset != 0) {
		t0h = (struct ibft_target *)(ibft + ibft_target0_offset);
		id = t0h->id;
		length = le16toh(t0h->length);
		index = t0h->index;
		flags = t0h->flags;
		if (id != IBFT_ID_TARGET) {
			printf("iBFT: Target0 Structure error (id=%d)\n", id);
			return (-1);
		}
		if (ibft_verbose) {
			printf("iBFT: TGT0: length=%d, index=%d, "
			    "flags=0x%x\n",
			    length, index, flags);
		}

		printf("TGT0: ");
		printf("Target IP address: ");
		ibft_print_address(t0h->ip);
		printf("\n");
		printf("TGT0: ");
		printf("Target Port: ");
		printf("%d\n", le16toh(t0h->port));
		printf("TGT0: ");
		printf("Target LUN: ");
		printf("%jx\n", (uintmax_t)le64toh(t0h->lun));

		if (ibft_verbose) {
			printf("TGT0: ");
			printf("CHAP type: ");
			printf("%d\n", t0h->chap_type);

			printf("TGT0: ");
			printf("NIC index: ");
			printf("%d\n", t0h->nic_index);
		}

		name_length = t0h->name_length;
		name_offset = t0h->name_offset;
		if (name_offset != 0) {
			printf("TGT0: ");
			printf("Target name: ");
			printf("%.*s\n", name_length, (ibft + name_offset));
		}

		if (ibft_verbose) {
			name_length = t0h->chap_name_length;
			name_offset = t0h->chap_name_offset;
			if (name_offset != 0) {
				printf("TGT0: ");
				printf("CHAP name: ");
				printf("%.*s\n", name_length,
				    (ibft + name_offset));
			}
			name_length = t0h->chap_secret_length;
			name_offset = t0h->chap_secret_offset;
			if (name_offset != 0) {
				printf("TGT0: ");
				printf("CHAP secret: ");
				printf("%.*s\n", name_length,
				    (ibft + name_offset));
			}

			name_length = t0h->rev_chap_name_length;
			name_offset = t0h->rev_chap_name_offset;
			if (name_offset != 0) {
				printf("TGT0: ");
				printf("Reverse CHAP name: ");
				printf("%.*s\n", name_length,
				    (ibft + name_offset));
			}
			name_length = t0h->rev_chap_secret_length;
			name_offset = t0h->rev_chap_secret_offset;
			if (name_offset != 0) {
				printf("TGT0: ");
				printf("Reverse CHAP secret: ");
				printf("%.*s\n", name_length,
				    (ibft + name_offset));
			}
		}
	}

	/* NIC1 Structure */
	if (ibft_nic1_offset != 0) {
		n1h = (struct ibft_nic *)(ibft + ibft_nic1_offset);
		id = n1h->id;
		length = le16toh(n1h->length);
		index = n1h->index;
		flags = n1h->flags;
		if (id != IBFT_ID_NIC) {
			printf("iBFT: NIC1 Structure error (id=%d)\n", id);
			return (-1);
		}
		if (ibft_verbose) {
			printf("iBFT: NIC1: length=%d, index=%d, "
			    "flags=0x%x\n",
			    length, index, flags);
		}
	}

	/* Target1 Structure */
	if (ibft_target1_offset != 0) {
		t1h = (struct ibft_target *)(ibft + ibft_target1_offset);
		id = t1h->id;
		length = le16toh(t1h->length);
		index = t1h->index;
		flags = t1h->flags;
		if (id != IBFT_ID_TARGET) {
			printf("iBFT: Target1 Structure error (id=%d)\n", id);
			return (-1);
		}
		if (ibft_verbose) {
			printf("iBFT: TGT1: length=%d, index=%d, "
			    "flags=0x%x\n",
			    length, index, flags);
		}
	}
	return (0);
}

/* search "iBFT" signature from range 512K -> 1024K */
static uint8_t *
ibft_search_signature(uint8_t *addr, size_t size)
{
	size_t n;

	/* The method is 3.3 of specification */
	for (n = IBFT_LOW_ADDR; (n + IBFT_ALIGN) <= IBFT_HIGH_ADDR
		     && (n + IBFT_ALIGN) <= size; n += IBFT_ALIGN) {
		if ((memcmp(addr + n, IBFT_SIGNATURE,
			IBFT_SIGNATURE_LENGTH) == 0) ||
		    (memcmp(addr + n, ACPI_SIG_IBFT,
			IBFT_SIGNATURE_LENGTH) == 0)) {
			return (addr + n);
		}
	}
	return (NULL);
}

/* Look up ACPI IBFT table */
static uint8_t *
ibft_acpi_lookup(void)
{
	ACPI_TABLE_IBFT *ibft;
	/*ACPI_IBFT_HEADER *ibft_hdr, *end;*/
	ACPI_STATUS status;

	status = AcpiGetTable(ACPI_SIG_IBFT, 1, (ACPI_TABLE_HEADER **)&ibft);
	if (ACPI_FAILURE(status)) {
		status = AcpiGetTable(IBFT_SIGNATURE, 1, (ACPI_TABLE_HEADER **)&ibft);
		if (ACPI_FAILURE(status))
			return (NULL);
	}
	return (uint8_t *)ibft;
}

int
ibft_init(void)
{
	int error, need_unmap;
	uint8_t *vaddr, *p;
	uint32_t paddr;
	p = ibft_acpi_lookup();
	if (p != NULL) {
		if (ibft_verbose) {
			printf("found iBFT via ACPI\n");
		}
		need_unmap = 0;
	}
	else {
		/* search signature */
		vaddr = pmap_mapdev((vm_paddr_t)0, (vm_size_t)IBFT_HIGH_ADDR);
		need_unmap = 1;
		p = ibft_search_signature(vaddr, IBFT_HIGH_ADDR);
		if (p != NULL) {
			paddr = (uint32_t)(uintptr_t)(p - vaddr);
			if (ibft_verbose) {
				printf("found iBFT via lowmem at 0x%x\n", paddr);
			}
		}
		else {
			if (ibft_verbose) {
				printf("iBFT not found\n");
			}
		}
	}
	if (p != NULL) {
		/* retrieve offsets */
		error = ibft_parse_structure(p);
		if (error) {
			if (ibft_verbose) {
				printf("iBFT error\n");
			}
			if (need_unmap == 1) {
#if __FreeBSD_version >= 1400070
				pmap_unmapdev(vaddr,
#else
				pmap_unmapdev((vm_offset_t)vaddr,
#endif
					(vm_size_t)IBFT_HIGH_ADDR);
			}
			return (error);
		}
		ibft_signature = p;
	}
	return (0);
}
