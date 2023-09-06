/*-
 * Copyright (c) 2010-2015 Daisuke Aoyama <aoyama@peach.ne.jp>
 * Copyright (c) 2021-2023 John Nielsen <john@jnielsen.net>
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <net/route.h>
#if __FreeBSD_version >= 1300091
#include <net/route/route_ctl.h>
#endif
#include "ibft.h"
#include "isboot.h"

static char *isboot_driver_version = "0.2.16-alpha";

/* boot iSCSI initiator and target */
uint8_t isboot_initiator_name[ISBOOT_NAME_MAX];
uint8_t isboot_target_name[ISBOOT_NAME_MAX];
uint8_t isboot_initiator_address[IBFT_IP_LEN];
uint8_t isboot_target_address[IBFT_IP_LEN];
uint8_t isboot_initiator_address_string[ISBOOT_ADDR_MAX];
uint8_t isboot_target_address_string[ISBOOT_ADDR_MAX];
uint32_t isboot_target_port;
uint64_t isboot_target_lun;
uint32_t isboot_nic_prefix;
uint8_t isboot_nic_gateway_string[ISBOOT_ADDR_MAX];

/* iBFT CHAP settings */
int isboot_chap_type = 0;
uint8_t isboot_chap_name[ISBOOT_CHAP_MAX];
uint8_t isboot_chap_secret[ISBOOT_CHAP_MAX];
uint8_t isboot_rev_chap_name[ISBOOT_CHAP_MAX];
uint8_t isboot_rev_chap_secret[ISBOOT_CHAP_MAX];

/* flags */
int isboot_iscsi_running = 0;
int isboot_stop_flag = 0;

/* sysctl (iBFT) */
SYSCTL_NODE(_hw, OID_AUTO, ibft, CTLFLAG_RD, 0, "iBFT parameters");
SYSCTL_STRING(_hw_ibft, OID_AUTO, initiator_name, CTLFLAG_RD, &isboot_initiator_name, 0, "iBFT initiator name");
SYSCTL_STRING(_hw_ibft, OID_AUTO, initiator_address, CTLFLAG_RD, &isboot_initiator_address_string, 0, "iBFT initiator address");
SYSCTL_STRING(_hw_ibft, OID_AUTO, target_name, CTLFLAG_RD, &isboot_target_name, 0, "iBFT target name");
SYSCTL_STRING(_hw_ibft, OID_AUTO, target_address, CTLFLAG_RD, &isboot_target_address_string, 0, "iBFT target address");
SYSCTL_UINT(_hw_ibft, OID_AUTO, target_port, CTLFLAG_RD, &isboot_target_port, 0, "iBFT target port");
SYSCTL_QUAD(_hw_ibft, OID_AUTO, target_lun, CTLFLAG_RD, &isboot_target_lun, 0, "iBFT target lun");
SYSCTL_UINT(_hw_ibft, OID_AUTO, nic_prefix, CTLFLAG_RD, &isboot_nic_prefix, 0, "iBFT nic prefix");
SYSCTL_STRING(_hw_ibft, OID_AUTO, nic_gateway, CTLFLAG_RD, &isboot_nic_gateway_string, 0, "iBFT nic gateway");

/* tunables */
static u_int isboot_ibft_acpi_table = 1;
TUNABLE_INT("hw.ibft.acpi_table", &isboot_ibft_acpi_table);
SYSCTL_UINT(_hw_ibft, OID_AUTO, acpi_table, CTLFLAG_RDTUN, &isboot_ibft_acpi_table, 0, "ACPI table index for iBFT");
u_int isboot_ibft_verbose = 0;
TUNABLE_INT("hw.ibft.verbose", &isboot_ibft_verbose);
SYSCTL_UINT(_hw_ibft, OID_AUTO, verbose, CTLFLAG_RDTUN, &isboot_ibft_verbose, 0, "Show verbose boot messages for iBFT");

/* sysctl (isboot) */
static struct sysctl_ctx_list isboot_clist;
uint8_t isboot_boot_nic[ISBOOT_SYSCTL_STR_MAX];
uint8_t isboot_boot_device[ISBOOT_SYSCTL_STR_MAX];
u_int isboot_trace = 0;
TUNABLE_INT("net.isboot.debug", &isboot_trace);

#define ISBOOT_TRACE(...) do { if(isboot_trace != 0) printf(__VA_ARGS__); } while (0)
#ifdef MODDEBUG
#define ISBOOT_MODTRACE(...) do { printf(__VA_ARGS__); } while (0)
#else
#define ISBOOT_MODTRACE(...)
#endif

char *
isboot_get_boot_nic(void)
{
	if (strlen(isboot_boot_nic) == 0)
		return (NULL);
	return (isboot_boot_nic);
}

char *
isboot_get_boot_device(void)
{
	if (strlen(isboot_boot_device) == 0)
		return (NULL);
	return (isboot_boot_device);
}

int
isboot_is_v4addr(uint8_t *addr)
{
	uint32_t n0, n1, n2;

	/* RFC2373 2.5.4 */
	n0 = be32toh(*(uint32_t *)(addr + 0));
	n1 = be32toh(*(uint32_t *)(addr + 4));
	n2 = be32toh(*(uint32_t *)(addr + 8));
	if (n0 == 0 && n1 == 0 && n2 == 0x0000ffffU)
		return (1);	/* IPv4-mapped IPv6 */
	else
		return (0);	/* IPv6 */
}

int
isboot_is_zero_v4addr(uint8_t *addr)
{
	uint32_t n0, n1, n2, n3;

	/* RFC2373 2.5.4 */
	n0 = be32toh(*(uint32_t *)(addr + 0));
	n1 = be32toh(*(uint32_t *)(addr + 4));
	n2 = be32toh(*(uint32_t *)(addr + 8));
	n3 = be32toh(*(uint32_t *)(addr +12));
	if (n0 == 0 && n1 == 0 && n2 == 0x0000ffffU && n3 == 0)
		return (1);	/* IPv4 zero addr */
	else
		return (0);	/* IPv6 or IPv4 non-zero */
}

/* find interface by MAC address */
#if __FreeBSD_version >= 1400094
static u_int
get_ifp_lladr_cb(void *lladdr, struct sockaddr_dl *sdl, u_int count)
{
	if (count > 0)
		return 0;
	if (memcmp((uint8_t *)lladdr, LLADDR(sdl), ETHER_ADDR_LEN) == 0)
		return 1;
	return 0;
}

static if_t
#else
static struct ifnet *
#endif
isboot_get_ifp_by_mac(uint8_t *lladdr)
{
#if __FreeBSD_version >= 1400094
	if_t ifp;
	struct if_iter iter;
	u_int count;
#else
	struct ifaddr *ifa;
	struct ifnet *ifp;
#endif

	if (lladdr == NULL)
		return (NULL);

#if __FreeBSD_version >= 1400094
	for (ifp = if_iter_start(&iter); ifp != NULL; ifp = if_iter_next(&iter)) {
		count = if_foreach_lladdr(ifp, get_ifp_lladr_cb, lladdr);
		if (count > 0)
			break;
	}
	if_iter_finish(&iter);
#else
	IFNET_RLOCK();
	CK_STAILQ_FOREACH(ifp, &V_ifnet, if_link)
		CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_LINK)
				continue;
			if (memcmp(lladdr,
				LLADDR((struct sockaddr_dl *)ifa->ifa_addr),
				ETHER_ADDR_LEN) == 0)
				goto done;
		}
	ifp = NULL;
done:
	IFNET_RUNLOCK();
#endif
	return (ifp);
}

/* remove all address and set new IPv4 address/mask to specified interface */
static int
#if __FreeBSD_version >= 1400094
isboot_set_v4addr(if_t ifp, struct sockaddr_in *addr, int prefix)
#else
isboot_set_v4addr(struct ifnet *ifp, struct sockaddr_in *addr, int prefix)
#endif
{
	struct ifreq ifr;
	struct ifaliasreq ifra, ifra2;
	struct sockaddr_in *sin, *osin;
	struct thread *td;
	uint32_t mask;
	int error;

	if (addr->sin_family != AF_INET)
		return (EINVAL);

	memset(&ifr, 0, sizeof(ifr));
	memset(&ifra, 0, sizeof(ifra));
	memset(&ifra2, 0, sizeof(ifra2));
	td = curthread;

	/* convert prefix to mask bits */
	if (prefix < 0 || prefix > 32)
		return (EINVAL);
	mask = ~0 << (32 - prefix);

	/* address */
	sin = (struct sockaddr_in *)&ifra.ifra_addr;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr->sin_addr.s_addr;

	/* netmask */
	sin = (struct sockaddr_in *)&ifra.ifra_mask;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(mask);

	/* remove old address */
	for (;;) {
		error = in_control(NULL, SIOCGIFADDR, (caddr_t)&ifr,
		    ifp, td);
		if (error == EADDRNOTAVAIL)
			break;
		if (error) {
			printf("in_control error\n");
			return (error);
		}
		osin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin = (struct sockaddr_in *)&ifra2.ifra_addr;
		memcpy(sin, osin, sizeof(*sin));
		error = in_control(NULL, SIOCDIFADDR, (caddr_t)&ifra2,
		    ifp, td);
		if (error) {
			printf("in_control error\n");
			return (error);
		}
	}

	/* set new address/mask */
	error = in_control(NULL, SIOCAIFADDR, (caddr_t)&ifra, ifp, td);
	if (error) {
		printf("in_control error\n");
		return (error);
	}
	return (0);
}

/* remove all address and set new IPv6 address/mask to specified interface */
static int
#if __FreeBSD_version >= 1400094
isboot_set_v6addr(if_t ifp, struct sockaddr_in6 *addr, int prefix)
#else
isboot_set_v6addr(struct ifnet *ifp, struct sockaddr_in6 *addr, int prefix)
#endif
{
	struct ifreq ifr;
	struct in6_aliasreq ifra, ifra2;
	struct sockaddr_in6 *sin6, *osin6;
	struct thread *td;
	uint32_t mask;
	int error;
	int i;

	if (addr->sin6_family != AF_INET6)
		return (EINVAL);

	memset(&ifr, 0, sizeof(ifr));
	memset(&ifra, 0, sizeof(ifra));
	memset(&ifra2, 0, sizeof(ifra2));
	td = curthread;

	/* convert prefix to mask bits */
	if (prefix < 0 || prefix > 128)
		return (EINVAL);
	mask = ~0 << (8 - (prefix % 8));

	/* address */
	sin6 = (struct sockaddr_in6 *)&ifra.ifra_addr;
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	memcpy(&sin6->sin6_addr, &addr->sin6_addr, (128/8));

	/* netmask */
	sin6 = (struct sockaddr_in6 *)&ifra.ifra_prefixmask;
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	for (i = 0; i < (prefix / 8); i++)
		sin6->sin6_addr.s6_addr[i] = 0xffU;
	if ((prefix % 8) != 0)
		sin6->sin6_addr.s6_addr[i] = mask;

	/* lifetime */
	ifra.ifra_lifetime.ia6t_expire = 0;
	ifra.ifra_lifetime.ia6t_preferred = 0;
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	/* remove old address */
	for (;;) {
		error = in6_control(NULL, SIOCGIFADDR, (caddr_t)&ifr,
		    ifp, td);
		if (error == EADDRNOTAVAIL)
			break;
		if (error) {
			printf("in6_control error\n");
			return (error);
		}
		osin6 = (struct sockaddr_in6 *)&ifr.ifr_addr;
		sin6 = (struct sockaddr_in6 *)&ifra2.ifra_addr;
		memcpy(sin6, osin6, sizeof(*sin6));
		error = in6_control(NULL, SIOCDIFADDR, (caddr_t)&ifra2,
		    ifp, td);
		if (error) {
			printf("in6_control error\n");
			return (error);
		}
	}

	/* set new address/mask */
	error = in6_control(NULL, SIOCAIFADDR_IN6, (caddr_t)&ifra, ifp, td);
	if (error) {
		printf("in6_control error\n");
		return (error);
	}
	return (0);
}

static int
isboot_set_v4gw(struct sockaddr_in *gateway)
{
	struct sockaddr_in dst;
	struct sockaddr_in netmask;
#if __FreeBSD_version >= 1300091
	struct rt_addrinfo info;
	struct rib_cmd_info rc;
#endif

	int error;

	if (gateway->sin_family != AF_INET)
		return (EINVAL);

	memset(&dst, 0, sizeof(dst));
	memset(&netmask, 0, sizeof(netmask));

	/* dst=0.0.0.0/0 (default) */
	dst.sin_len = sizeof(dst);
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(0);
	netmask.sin_len = sizeof(netmask);
	netmask.sin_family = AF_INET;
	netmask.sin_addr.s_addr = htonl(0);

	/* delete gateway if exists */
#if __FreeBSD_version >= 1300091
	bzero((caddr_t)&info, sizeof(info));
	info.rti_flags = 0;
	info.rti_info[RTAX_DST] = (struct sockaddr *)&dst;
	info.rti_info[RTAX_NETMASK] = (struct sockaddr *)&netmask;
	info.rti_info[RTAX_GATEWAY] = (struct sockaddr *)gateway;
	error = rib_action(RT_DEFAULT_FIB, RTM_DELETE, &info, &rc);
#else
    error = rtrequest_fib(RTM_DELETE, (struct sockaddr *)&dst,
	    (struct sockaddr *)gateway, (struct sockaddr *)&netmask,
	    0, NULL, RT_DEFAULT_FIB);
#endif
	if (error) {
		if (error != ESRCH) {
			printf("rtrequest RTM_DELETE error %d\n",
			    error);
			return (error);
		}
	}

	/* set new default gateway */
#if __FreeBSD_version >= 1300091
	bzero((caddr_t)&info, sizeof(info));
	info.rti_flags = RTF_GATEWAY | RTF_STATIC;
	info.rti_info[RTAX_DST] = (struct sockaddr *)&dst;
	info.rti_info[RTAX_NETMASK] = (struct sockaddr *)&netmask;
	info.rti_info[RTAX_GATEWAY] = (struct sockaddr *)gateway;
	error = rib_action(RT_DEFAULT_FIB, RTM_ADD, &info, &rc);
#else
	error = rtrequest_fib(RTM_ADD, (struct sockaddr *)&dst,
	    (struct sockaddr *)gateway, (struct sockaddr *)&netmask,
	    RTF_GATEWAY | RTF_STATIC, NULL, RT_DEFAULT_FIB);
#endif
	if (error) {
		printf("rtrequest RTM_ADD error %d\n", error);
		return (error);
	}
	return (0);
}

static int
isboot_set_v6gw(struct sockaddr_in6 *gateway)
{
	struct sockaddr_in6 dst;
	struct sockaddr_in6 netmask;
#if __FreeBSD_version >= 1300091
	struct rt_addrinfo info;
	struct rib_cmd_info rc;
#endif
	int error;

	if (gateway->sin6_family != AF_INET6)
		return (EINVAL);

	memset(&dst, 0, sizeof(dst));
	memset(&netmask, 0, sizeof(netmask));

	/* dst=[::]/0 (default) */
	dst.sin6_len = sizeof(dst);
	dst.sin6_family = AF_INET6;
	memset(&dst.sin6_addr, 0, 16);
	netmask.sin6_len = sizeof(netmask);
	netmask.sin6_family = AF_INET6;
	memset(&netmask.sin6_addr, 0, 16);

	/* delete gateway if exists */
#if __FreeBSD_version >= 1300091
	bzero((caddr_t)&info, sizeof(info));
	info.rti_flags = 0;
	info.rti_info[RTAX_DST] = (struct sockaddr *)&dst;
	info.rti_info[RTAX_NETMASK] = (struct sockaddr *)&netmask;
	info.rti_info[RTAX_GATEWAY] = (struct sockaddr *)gateway;
	error = rib_action(RT_DEFAULT_FIB, RTM_DELETE, &info, &rc);
#else
	error = rtrequest_fib(RTM_DELETE, (struct sockaddr *)&dst,
	    (struct sockaddr *)gateway, (struct sockaddr *)&netmask,
	    0, NULL, RT_DEFAULT_FIB);
#endif
	if (error) {
		if (error != ESRCH) {
			printf("rtrequest RTM_DELETE error %d\n",
			    error);
			return (error);
		}
	}

	/* set new default gateway */
#if __FreeBSD_version >= 1300091
	bzero((caddr_t)&info, sizeof(info));
	info.rti_flags = RTF_GATEWAY | RTF_STATIC;
	info.rti_info[RTAX_DST] = (struct sockaddr *)&dst;
	info.rti_info[RTAX_NETMASK] = (struct sockaddr *)&netmask;
	info.rti_info[RTAX_GATEWAY] = (struct sockaddr *)gateway;
	error = rib_action(RT_DEFAULT_FIB, RTM_ADD, &info, &rc);
#else
	error = rtrequest_fib(RTM_ADD, (struct sockaddr *)&dst,
	    (struct sockaddr *)gateway, (struct sockaddr *)&netmask,
	    RTF_GATEWAY | RTF_STATIC, NULL, RT_DEFAULT_FIB);
#endif
	if (error) {
		printf("rtrequest RTM_ADD error %d\n", error);
		return (error);
	}
	return (0);
}

static int
#if __FreeBSD_version >= 1400094
isboot_ifup(if_t ifp)
#else
isboot_ifup(struct ifnet *ifp)
#endif
{
	struct socket *so;
	struct ifreq ifr;
	struct thread *td;
	int error;

	memset(&ifr, 0, sizeof(ifr));
	td = curthread;
	error = socreate(AF_INET, &so, SOCK_DGRAM, 0, td->td_ucred, td);
	if (error) {
		printf("%s: socreate, error=%d\n", __func__, error);
		return (error);
	}

	/* boot NIC */
#if __FreeBSD_version >= 1400094
	strlcpy(ifr.ifr_name, if_name(ifp), sizeof(ifr.ifr_name));
#else
	strlcpy(ifr.ifr_name, ifp->if_xname, sizeof(ifr.ifr_name));
#endif

	/* set IFF_UP */
	error = ifioctl(so, SIOCGIFFLAGS, (caddr_t)&ifr, td);
	if (error) {
		printf("ifioctl SIOCGIFFLAGS\n");
		return (error);
	}
	ifr.ifr_flags |= IFF_UP;
	error = ifioctl(so, SIOCSIFFLAGS, (caddr_t)&ifr, td);
	if (error) {
		printf("ifioctl SIOCSIFFLAGS\n");
		return (error);
	}

	return (0);
}

static int
isboot_init(void)
{
	struct sockaddr_storage sa;
	struct sockaddr_in *gw4;
	struct sockaddr_in6 *gw6;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	struct sysctl_oid *oidp;
	struct ibft_initiator *ini;
	struct ibft_nic *nic0;
	struct ibft_target *tgt0;
#if __FreeBSD_version >= 1400094
	if_t ifp;
#else
	struct ifnet *ifp;
#endif
	uint8_t *ibft;
	int name_length, name_offset;
	int prefix;
	int error;

	ibft = ibft_get_signature();
	ini = ibft_get_initiator();
	nic0 = ibft_get_nic0();
	tgt0 = ibft_get_target0();

	/* not specified in iBFT? */
	if (ibft == NULL || ini == NULL || nic0 == NULL || tgt0 == NULL)
		return (ENXIO);

	/* find booted NIC from MAC address */
	ifp = isboot_get_ifp_by_mac(nic0->mac);
	if (ifp == NULL)
		return (ESRCH);
#if __FreeBSD_version >= 1400094
	printf("Boot NIC: %s\n", if_name(ifp));
#else
	printf("Boot NIC: %s\n", ifp->if_xname);
#endif

	/* interface UP */
	error = isboot_ifup(ifp);
	if (error) {
		printf("ifup error\n");
		return (error);
	}

	/* set IP in iBFT to the NIC */
	if (isboot_is_v4addr(tgt0->ip) && isboot_is_v4addr(nic0->ip)) {
		printf("Configure IPv4 by %s%d\n", "NIC", nic0->index);
		addr4 = (struct sockaddr_in *)&sa;
		memset(addr4, 0, sizeof(*addr4));
		addr4->sin_len = sizeof(*addr4);
		addr4->sin_family = AF_INET;
		memcpy(&addr4->sin_addr, &nic0->ip[12], 4);
		prefix = nic0->mask_prefix;
		error = isboot_set_v4addr(ifp, addr4, prefix);
	} else {
		printf("Configure IPv6 by %s%d\n", "NIC", nic0->index);
		addr6 = (struct sockaddr_in6 *)&sa;
		memset(addr6, 0, sizeof(*addr6));
		addr6->sin6_len = sizeof(*addr6);
		addr6->sin6_family = AF_INET6;
		memcpy(&addr6->sin6_addr, &nic0->ip[0], 16);
		prefix = nic0->mask_prefix;
		error = isboot_set_v6addr(ifp, addr6, prefix);
	}
	if (error) {
		printf("IP set error\n");
		return (error);
	}

	/* set default gateway */
	if (!ibft_is_zero_address(nic0->gateway) &&
	    !isboot_is_zero_v4addr(nic0->gateway)) {
		if (isboot_is_v4addr(tgt0->ip) && isboot_is_v4addr(nic0->ip)) {
			gw4 = (struct sockaddr_in *)&sa;
			memset(gw4, 0, sizeof(*gw4));
			gw4->sin_len = sizeof(*gw4);
			gw4->sin_family = AF_INET;
			memcpy(&gw4->sin_addr, &nic0->gateway[12], 4);
			error = isboot_set_v4gw(gw4);
		} else {
			gw6 = (struct sockaddr_in6 *)&sa;
			memset(gw6, 0, sizeof(*gw6));
			gw6->sin6_len = sizeof(*gw6);
			gw6->sin6_family = AF_INET6;
			memcpy(&gw6->sin6_addr, &nic0->gateway[0], 16);
			error = isboot_set_v6gw(gw6);
		}
		if (error) {
			printf("Gateway set error\n");
			return (error);
		}
	}

	/* TODO: DNS, etc */

	/* prepare values for iSCSI */
	name_length = ini->name_length;
	name_offset = ini->name_offset;
	snprintf(isboot_initiator_name, sizeof(isboot_initiator_name), "%.*s",
	    name_length, (ibft + name_offset));
	memcpy(isboot_initiator_address, &nic0->ip, IBFT_IP_LEN);
	isboot_addr2str(isboot_initiator_address_string,
	    sizeof(isboot_initiator_address_string), isboot_initiator_address);

	name_length = tgt0->name_length;
	name_offset = tgt0->name_offset;
	snprintf(isboot_target_name, sizeof(isboot_target_name), "%.*s",
	    name_length, (ibft + name_offset));
	memcpy(isboot_target_address, &tgt0->ip, IBFT_IP_LEN);
	isboot_addr2str(isboot_target_address_string,
	    sizeof(isboot_target_address_string), isboot_target_address);
	isboot_target_port = le16toh(tgt0->port);
	isboot_target_lun = le64toh(tgt0->lun);

	isboot_chap_type = tgt0->chap_type;
	memset(isboot_chap_name, 0, sizeof(isboot_chap_name));
	memset(isboot_chap_secret, 0, sizeof(isboot_chap_secret));
	memset(isboot_rev_chap_name, 0, sizeof(isboot_rev_chap_name));
	memset(isboot_rev_chap_secret, 0, sizeof(isboot_rev_chap_secret));
	if (isboot_chap_type == 1 || isboot_chap_type == 2) {
		/* 1=CHAP, 2=Mutual CHAP */
		name_length = tgt0->chap_name_length;
		name_offset = tgt0->chap_name_offset;
		snprintf(isboot_chap_name, sizeof(isboot_chap_name), "%.*s",
		    name_length, (ibft + name_offset));
		name_length = tgt0->chap_secret_length;
		name_offset = tgt0->chap_secret_offset;
		snprintf(isboot_chap_secret, sizeof(isboot_chap_secret),
		    "%.*s", name_length, (ibft + name_offset));

		if (isboot_chap_type == 1) {
			printf("CHAP Type: CHAP\n");
		} else if (isboot_chap_type == 2) {
			printf("CHAP Type: Mutual CHAP\n");

			name_length = tgt0->rev_chap_name_length;
			name_offset = tgt0->rev_chap_name_offset;
			snprintf(isboot_rev_chap_name,
			    sizeof(isboot_rev_chap_name),
			    "%.*s", name_length, (ibft + name_offset));
			name_length = tgt0->rev_chap_secret_length;
			name_offset = tgt0->rev_chap_secret_offset;
			snprintf(isboot_rev_chap_secret,
			    sizeof(isboot_rev_chap_secret),
			    "%.*s", name_length, (ibft + name_offset));
		}
	} else {
		if (bootverbose) {
			printf("CHAP Type: No CHAP\n");
		}
	}

	isboot_nic_prefix = nic0->mask_prefix;
	isboot_addr2str(isboot_nic_gateway_string,
	    sizeof(isboot_nic_gateway_string), nic0->gateway);

	/* sysctl */
	sysctl_ctx_init(&isboot_clist);
	oidp = SYSCTL_ADD_NODE(&isboot_clist,
	    SYSCTL_STATIC_CHILDREN(_net),
	    OID_AUTO, "isboot", CTLFLAG_RW, 0, "iSCSI boot driver");
	SYSCTL_ADD_STRING(&isboot_clist, SYSCTL_CHILDREN(oidp),
	    OID_AUTO, "version", CTLFLAG_RD, isboot_driver_version, 0,
	    "iSCSI boot driver version");
	SYSCTL_ADD_STRING(&isboot_clist, SYSCTL_CHILDREN(oidp),
	    OID_AUTO, "nic", CTLFLAG_RD, isboot_boot_nic, 0,
	    "iSCSI boot driver NIC");
	SYSCTL_ADD_STRING(&isboot_clist, SYSCTL_CHILDREN(oidp),
	    OID_AUTO, "device", CTLFLAG_RD, isboot_boot_device, 0,
	    "iSCSI boot driver device");
	SYSCTL_ADD_UINT(&isboot_clist, SYSCTL_CHILDREN(oidp),
	    OID_AUTO, "debug", CTLFLAG_RDTUN, &isboot_trace, 0,
	    "Show iSCSI boot driver debug (trace) messages");
#if __FreeBSD_version >= 1400094
	strlcpy(isboot_boot_nic, if_name(ifp),
#else
	strlcpy(isboot_boot_nic, ifp->if_xname,
#endif
	    sizeof(isboot_boot_nic));
	strlcpy(isboot_boot_device, "",
	    sizeof(isboot_boot_device));

	return (0);
}

static void
isboot_destroy(void)
{
	sysctl_ctx_free(&isboot_clist);
}

static void
isboot_version(void)
{
	printf("iSCSI boot driver version %s\n", isboot_driver_version);
}

static int
isboot_handler(module_t mod, int what, void *arg)
{
	int err = 0;
	int retry = 30;

	switch (what) {
	case MOD_LOAD:
		ISBOOT_MODTRACE("Load isboot\n");
		isboot_version();
		if (bootverbose)
			isboot_ibft_verbose = 1;
		(void)ibft_init();
		if (ibft_get_signature() != NULL) {
			err = isboot_init();
			if (err == 0) {
				err = isboot_iscsi_start();
				if (err) {
					printf("can't start iSCSI session\n");
				}
			}
		}
		err = 0;
		break;
	case MOD_UNLOAD:
		ISBOOT_MODTRACE("Unload isboot\n");
		if (ibft_get_signature() != NULL) {
			isboot_destroy();
		}
		if (isboot_iscsi_running != 0) {
			ISBOOT_MODTRACE("iSCSI session is still valid\n");
			err = EBUSY;
		}
		break;
	case MOD_SHUTDOWN:
		ISBOOT_MODTRACE("Shutdown isboot\n");
		if (isboot_iscsi_running != 0) {
			ISBOOT_MODTRACE("iSCSI session is still valid\n");
			err = EBUSY;
		}
		break;
	case MOD_QUIESCE:
		ISBOOT_MODTRACE("Quiesce isboot\n");
		if (isboot_iscsi_running != 0) {
			ISBOOT_MODTRACE("iSCSI session is still valid\n");
			isboot_stop_flag = 1;
			while (retry-- > 0) {
				tsleep(&isboot_iscsi_running, PWAIT,
				    "isboot", 1 * hz);
				if (isboot_iscsi_running == 0)
					break;
			}
			if (isboot_iscsi_running != 0) {
				printf("iSCSI session is still valid\n");
				err = EBUSY;
			}
		}
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return (err);
}

static moduledata_t mod_data = {
	"isboot",
	isboot_handler,
	0
};

MODULE_VERSION(isboot, 1);
MODULE_DEPEND(isboot, ether, 1, 1, 1);
MODULE_DEPEND(isboot, icl, 1, 1, 1);
MODULE_DEPEND(isboot, cam, 1, 1, 1);
/* Delay loading as long as possible to ensure NIC drivers and their dependencies have loaded first */
DECLARE_MODULE(isboot, mod_data, SI_SUB_ROOT_CONF-1, SI_ORDER_ANY);
