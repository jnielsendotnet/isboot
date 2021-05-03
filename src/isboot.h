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

#ifndef ISBOOT_H
#define ISBOOT_H

#define ISBOOT_NAME_MAX 256
#define ISBOOT_ADDR_MAX 64
#define ISBOOT_CHAP_MAX 256
#define ISBOOT_SYSCTL_STR_MAX 64
#define ISBOOT_MAX_LUNS 64

extern uint8_t isboot_initiator_name[ISBOOT_NAME_MAX];
extern uint8_t isboot_target_name[ISBOOT_NAME_MAX];
extern uint8_t isboot_initiator_address[IBFT_IP_LEN];
extern uint8_t isboot_target_address[IBFT_IP_LEN];
extern uint8_t isboot_initiator_address_string[ISBOOT_ADDR_MAX];
extern uint8_t isboot_target_address_string[ISBOOT_ADDR_MAX];
extern uint32_t isboot_target_port;
extern uint64_t isboot_target_lun;
extern int isboot_chap_type;
extern uint8_t isboot_chap_name[ISBOOT_CHAP_MAX];
extern uint8_t isboot_chap_secret[ISBOOT_CHAP_MAX];
extern uint8_t isboot_rev_chap_name[ISBOOT_CHAP_MAX];
extern uint8_t isboot_rev_chap_secret[ISBOOT_CHAP_MAX];
extern int isboot_iscsi_running;
extern int isboot_stop_flag;
extern uint8_t isboot_boot_nic[ISBOOT_SYSCTL_STR_MAX];
extern uint8_t isboot_boot_device[ISBOOT_SYSCTL_STR_MAX];

char *isboot_get_boot_nic(void);
char *isboot_get_boot_device(void);
int isboot_is_v4addr(uint8_t *addr);
int isboot_is_zero_v4addr(uint8_t *addr);
int isboot_iscsi_start(void);

void isboot_addr2str(char *buf, size_t size, uint8_t *addr);
void isboot_init_crc32c_table(void);
uint32_t isboot_update_crc32c(const uint8_t *buf, size_t len, uint32_t crc);
uint32_t isboot_fixup_crc32c(size_t total, uint32_t crc);
uint32_t isboot_crc32c(const uint8_t *buf, size_t len);
uint32_t isboot_iovec_crc32c(const struct iovec *iovp, int iovc, uint32_t offset, uint32_t len);
void isboot_dump(const char *label, const uint8_t *buf, size_t len);

#endif /* ISBOOT_H */
