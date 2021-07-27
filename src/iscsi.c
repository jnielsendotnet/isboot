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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ctype.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/kthread.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/md5.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <machine/stdarg.h>
#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt_sim.h>
#include <cam/cam_periph.h>
#include <cam/cam_xpt_periph.h>
#include <cam/scsi/scsi_message.h>

/* iscsi_initiator related */
#ifdef USE_SYSTEM_ISCSI_HEADER
#include <dev/iscsi_initiator/iscsi.h>
#include <dev/iscsi_initiator/iscsivar.h>
/* XXX this includes define of CmdSN, ExpStSN, MaxCmdSN */
#undef CmdSN
#undef ExpStSN
#undef MaxCmdSN
#else /* !USE_SYSTEM_ISCSI_HEADER */
#include "iscsi_compat.h"
#endif /* USE_SYSTEM_ISCSI_HEADER */

/* local headers */
#include "ibft.h"
#include "isboot.h"

/*#define DEBUG*/
#define ISBOOT_SOCK_TIMEOUT 30
#define ISBOOT_CAM_TAGS 32
#define ISBOOT_CAM_MAX_TAGS 255
#define ISBOOT_CHAP_CHALLENGE_LEN 1024
#define ISBOOT_CHAP_CHALLENGE_STRLEN (3 + (ISBOOT_CHAP_CHALLENGE_LEN * 2))
#define ISBOOT_CHAP_MAX_DIGEST_LEN 16
#define ISBOOT_CHAP_MAX_DIGEST_STRLEN (3 + (ISBOOT_CHAP_MAX_DIGEST_LEN * 2))
#define ISBOOT_CHAP_MAX_USER_LEN (ISBOOT_NAME_MAX)

MALLOC_DEFINE(M_ISBOOT, "iSCSI boot", "iSCSI boot driver");
MALLOC_DEFINE(M_ISBOOTMEXT, "iSB MEXT", "iSCSI boot mbuf ext");
MALLOC_DEFINE(M_ISBOOTPDUBUF, "iSB PDUBUF", "iSCSI boot pdu buf");
MALLOC_DEFINE(M_ISBOOTSTR, "iSB string", "iSCSI boot string");

static uint32_t isboot_itt = 0;

struct isboot_task {
	TAILQ_ENTRY(isboot_task) tasks;
	uint64_t LUN;
	uint32_t ITT;
	uint32_t cmdsn;
	union ccb *ccb;
};

struct action_xmit_task {
	TAILQ_ENTRY(action_xmit_task) tasks;
	union ccb *ccb;
};

struct isboot_chap {
	char *algorithm;
        char *user;
        char *secret;
        char *muser;
        char *msecret;

	uint8_t chap_id[1];
	uint8_t chap_mid[1];
	int chap_challenge_len;
	uint8_t chap_challenge[ISBOOT_CHAP_CHALLENGE_LEN];
	int chap_mchallenge_len;
	uint8_t chap_mchallenge[ISBOOT_CHAP_CHALLENGE_LEN];
	uint8_t chap_mchallenge_string[ISBOOT_CHAP_CHALLENGE_STRLEN];
	int chap_response_len;
	uint8_t chap_response[ISBOOT_CHAP_MAX_DIGEST_LEN];
	uint8_t chap_response_string[ISBOOT_CHAP_MAX_DIGEST_STRLEN];

	uint8_t chap_muser[ISBOOT_CHAP_MAX_USER_LEN];
	int chap_mresponse_len;
	uint8_t chap_mresponse[ISBOOT_CHAP_MAX_DIGEST_LEN];
	uint8_t chap_mresponse_string[ISBOOT_CHAP_MAX_DIGEST_STRLEN];
};

struct isboot_sess {
	struct proc *pp;
	struct thread *td;
	struct socket *so;
	struct thread *action_xmit_td;
	// NOT USE
	//isc_session_t *sp;
	int fd;
	int timeout;

	char initiator_name[ISBOOT_NAME_MAX];
	char target_name[ISBOOT_NAME_MAX];
	uint32_t family;
	uint8_t initiator_address[IBFT_IP_LEN];
	uint8_t target_address[IBFT_IP_LEN];
	uint16_t port;
	uint64_t lun;

	uint64_t isid;
	uint16_t tsih;
	uint16_t cid;

	int header_digest;
	int data_digest;
	int full_feature;
	int reconnect;

	int stage;
	int chap_stage;
	int discovery;
	struct isboot_chap auth;
	int authenticated;
	int req_auth;
	int req_mutual;

	uint32_t cws;
	uint32_t cmdsn;
	uint32_t statsn;
	uint32_t itt;

	struct mtx xmit_mtx;
	struct mtx sn_mtx;

	/* cam task */
	uint32_t tags;
	struct mtx task_mtx;
	TAILQ_HEAD(,isboot_task) taskq;

	/* xmit queue */
	bool action_xmit_exit;
	struct cv action_xmit_cv;
	struct mtx action_xmit_mtx;
	TAILQ_HEAD(,action_xmit_task) action_xmitq;

	/* cam stuff */
	uint32_t unit;
	struct cam_sim *sim;
	struct cam_path *path;
	struct mtx cam_mtx;
	int cam_rescan_done;
	int cam_rescan_in_progress;
	int cam_device_installed;
	int cam_qfreeze;

	/* iscsi_initiator specific */
	isc_opt_t opt;
};

static struct isboot_sess isboot_g_sess;

#define ISBOOT_NO_STAGE -1
#define ISBOOT_SECURITYNEGOTIATION 0
#define ISBOOT_LOGINOPERATIONALNEGOTIATION 1
#define ISBOOT_FULLFEATUREPHASE 3

#define ISBOOT_CHAP_NONE 0
#define ISBOOT_CHAP_WAIT_A 1
#define ISBOOT_CHAP_WAIT_NR 2
#define ISBOOT_CHAP_MUTUAL 3
#define ISBOOT_CHAP_END 4

#ifdef DEBUG
#define ISBOOT_ERROR(...) do { printf(__VA_ARGS__); } while (0)
#define ISBOOT_TRACE(...) do { printf(__VA_ARGS__); } while (0)
#define ISBOOT_TRACEDUMP(LABEL, BUF, LEN) \
	do { isboot_dump((LABEL), (BUF), (LEN)); } while (0)
#else
#define ISBOOT_ERROR(...) do { printf(__VA_ARGS__); } while (0)
#define ISBOOT_TRACE(...)
#define ISBOOT_TRACEDUMP(LABEL, BUF, LEN)
#endif

#ifdef ISBOOT_OPT_PREFERRED_HEADER_DIGEST
static char *isboot_opt_hd = "CRC32C,None";
#else
static char *isboot_opt_hd = "None,CRC32C";
#endif
#ifdef ISBOOT_OPT_PREFERRED_DATA_DIGEST
static char *isboot_opt_dd = "CRC32C,None";
#else
static char *isboot_opt_dd = "None,CRC32C";
#endif

void
isboot_addr2str(char *buf, size_t size, uint8_t *addr)
{

	/* convert network binary to presentation string */
	if (isboot_is_v4addr(addr)) {
		/* IPv4-mapped IPv6 */
		snprintf(buf, size, "%d.%d.%d.%d",
		    addr[12], addr[13], addr[14], addr[15]);
	} else {
		/* IPv6 */
		snprintf(buf, size, "%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x",
		    addr[0], addr[1], addr[2], addr[3],
		    addr[4], addr[5], addr[6], addr[7],
		    addr[8], addr[9], addr[10], addr[11],
		    addr[12], addr[13], addr[14], addr[15]);
	}
}

static void *
isboot_malloc(size_t size)
{
	void *p;

	p = malloc(size, M_ISBOOT, M_NOWAIT);
	if (p == NULL)
		panic("no memory");
	return (p);
}

static void *
isboot_malloc_mext(size_t size)
{
	void *p;

	p = malloc(size, M_ISBOOTMEXT, M_NOWAIT);
	if (p == NULL)
		panic("no memory");
	return (p);
}

static void *
isboot_malloc_pdubuf(size_t size)
{
	void *p;

	p = malloc(size, M_ISBOOTPDUBUF, M_NOWAIT);
	if (p == NULL)
		panic("no memory");
	return (p);
}

static char *
isboot_strdup(const char *s)
{
	char *p;
	size_t n;

	n = strlen(s);
	p = malloc(n + 1, M_ISBOOTSTR, M_NOWAIT);
	if (p == NULL)
		panic("no memory");
	memcpy(p, s, n);
	p[n] = '\0';
	ISBOOT_TRACE("strdup(%s)%zu\n", s, n);
	return (p);
}

static void
isboot_free(void *p)
{

	if (p == NULL)
		return;
	free(p, M_ISBOOT);
}

static void
isboot_free_mext(void *p)
{

	if (p == NULL)
		return;
	free(p, M_ISBOOTMEXT);
}

static void
isboot_free_pdubuf(void *p)
{

	if (p == NULL)
		return;
	free(p, M_ISBOOTPDUBUF);
}

static void
isboot_free_str(void *p)
{

	if (p == NULL)
		return;
	ISBOOT_TRACE("free[%s]\n", (char *)p);
	free(p, M_ISBOOTSTR);
}

static uint64_t
isboot_get_isid(int qualifier)
{
	uint64_t isid, T, A, B, C, D;

	/* RFC3720 10.12.5 */
	T = 2;
	A = 0;
	B = 0x4953;
	C = 0x42;
	D = (uint64_t)(qualifier & 0xffff);

	isid  = (T & 0x03U)   << 46;
	isid |= (A & 0x3fU)   << 40;
	isid |= (B & 0xffffU) << 24;
	isid |= (C & 0xffU)   << 16;
	isid |= (D & 0xffffU);
	isid &= ~(1ULL << 48);
	return (isid);
}

static uint32_t
isboot_get_next_itt(struct isboot_sess *sess)
{
	uint32_t itt;

	itt = ++isboot_itt;
	if (itt == 0xffffffffU) {
		itt = ++isboot_itt;
	}
	sess->itt = itt;
	return (itt);
}

static int
isboot_connect(struct isboot_sess *sess)
{
	struct socket *so;
	struct sockopt opt;
	struct sockaddr_storage sa;
	struct sockaddr_in *sav4;
	struct sockaddr_in6 *sav6;
	struct timeval tv;
	int error;
	int optarg;
	int family;

	/* initial socket */
	if (sess->so != NULL) {
		soclose(sess->so);
		sess->so = NULL;
	}

	/* reject v4->v6 connect */
	memset(&sa, 0, sizeof(sa));
	if (isboot_is_v4addr(sess->target_address)) {
		if (!isboot_is_v4addr(sess->initiator_address)) {
			ISBOOT_ERROR("IP address family error\n");
			return (EINVAL);
		}
		sav4 = (struct sockaddr_in *)&sa;
		sav4->sin_len = sizeof(*sav4);
		sav4->sin_family = AF_INET;
		sav4->sin_port = htons(sess->port);
		memcpy(&sav4->sin_addr, &sess->target_address[12], 4);
	} else {
		if (isboot_is_v4addr(sess->initiator_address)) {
			ISBOOT_ERROR("IP address family error\n");
			return (EINVAL);
		}
		sav6 = (struct sockaddr_in6 *)&sa;
		sav6->sin6_len = sizeof(*sav6);
		sav6->sin6_family = AF_INET6;
		sav6->sin6_port = htons(sess->port);
		memcpy(&sav6->sin6_addr, &sess->target_address[0], 16);
	}

	/* open socket */
	ISBOOT_TRACE("open socket\n");
	sess->family = sa.ss_family;
	family = (sess->family == AF_INET) ? PF_INET : PF_INET6;
	error = socreate(family, &so, SOCK_STREAM, 0, sess->td->td_ucred,
	    sess->td);
	if (error) {
		ISBOOT_ERROR("socket error\n");
		return (error);
	}

	/* set socket option */
	optarg = 1;
	memset(&opt, 0, sizeof(opt));
	opt.sopt_dir = SOPT_SET;
	opt.sopt_level = IPPROTO_TCP;
	opt.sopt_name = TCP_NODELAY;
	opt.sopt_val = &optarg;
	opt.sopt_valsize = sizeof(optarg);
	error = sosetopt(so, &opt);
	if (error) {
		ISBOOT_ERROR("setsockopt error\n");
		soclose(so);
		return (error);
	}
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = sess->timeout;
	tv.tv_usec = 0;
	memset(&opt, 0, sizeof(opt));
	opt.sopt_dir = SOPT_SET;
	opt.sopt_level = SOL_SOCKET;
	opt.sopt_name = SO_RCVTIMEO;
	opt.sopt_val = &tv;
	opt.sopt_valsize = sizeof(tv);
	error = sosetopt(so, &opt);
	if (error) {
		ISBOOT_ERROR("setsockopt error\n");
		soclose(so);
		return (error);
	}
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = sess->timeout;
	tv.tv_usec = 0;
	memset(&opt, 0, sizeof(opt));
	opt.sopt_dir = SOPT_SET;
	opt.sopt_level = SOL_SOCKET;
	opt.sopt_name = SO_SNDTIMEO;
	opt.sopt_val = &tv;
	opt.sopt_valsize = sizeof(tv);
	error = sosetopt(so, &opt);
	if (error) {
		ISBOOT_ERROR("setsockopt error\n");
		soclose(so);
		return (error);
	}

	/* connect to the target */
	ISBOOT_TRACE("try connect...(%x)\n", curthread->td_tid);
	error = soconnect(so, (struct sockaddr *)&sa, sess->td);
	if (error) {
		ISBOOT_ERROR("connect error\n");
		soclose(so);
		return (error);
	}

	/* wait for the connection to complete */
	ISBOOT_TRACE("wait connect...\n");
	SOCK_LOCK(so);
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = msleep(&so->so_timeo, SOCK_MTX(so), PSOCK | PCATCH,
		    "isboot", 0);
		if (error) {
			if (error == EINTR || error == ERESTART)
				;
			break;
		}
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	SOCK_UNLOCK(so);
	if (error) {
		soclose(so);
		return (error);
	}

	/* now session is valid */
	ISBOOT_TRACE("old so=%p, new so=%p\n", sess->so, so);
	sess->so = so;
	return (0);
}

/* iscsi_initiator.ko handling based on iscsi-2.2.4 by Daniel Braniss */
/* and based on istgt-20100606 by Daisuke Aoyama */

// NOT USE
//#define ISCSI_CTLDEV "/dev/iscsi"
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

/* defined in RFC3720(12.1) */
static uint32_t isboot_crc32c_initial    = 0xffffffffUL;
static uint32_t isboot_crc32c_xor        = 0xffffffffUL;
static uint32_t isboot_crc32c_polynomial = 0x1edc6f41UL;
#define ISBOOT_USE_CRC32C_TABLE
#ifdef ISBOOT_USE_CRC32C_TABLE
static uint32_t isboot_crc32c_table[256];
static int isboot_crc32c_initialized = 0;
#endif /* ISBOOT_USE_CRC32C_TABLE */

static uint32_t
isboot_reflect(uint32_t val, int bits)
{
	int i;
	uint32_t r;

	if (bits < 1 || bits > 32)
		return (0);
	r = 0;
	for (i = 0; i < bits; i++) {
		r |= ((val >> ((bits - 1) - i)) & 1) << i;
	}
	return (r);
}

#ifdef ISBOOT_USE_CRC32C_TABLE
void
isboot_init_crc32c_table(void)
{
	int i, j;
	uint32_t val;
	uint32_t reflect_polynomial;

	reflect_polynomial = isboot_reflect(isboot_crc32c_polynomial, 32);
	for (i = 0; i < 256; i++) {
		val = i;
		for (j = 0; j < 8; j++) {
			if (val & 1) {
				val = (val >> 1) ^ reflect_polynomial;
			} else {
				val = (val >> 1);
			}
		}
		isboot_crc32c_table[i] = val;
	}
	isboot_crc32c_initialized = 1;
}
#endif /* ISBOOT_USE_CRC32C_TABLE */

uint32_t
isboot_update_crc32c(const uint8_t *buf, size_t len, uint32_t crc)
{
	size_t s;
#ifndef ISBOOT_USE_CRC32C_TABLE
	int i;
	uint32_t val;
	uint32_t reflect_polynomial;
#endif /* ISBOOT_USE_CRC32C_TABLE */

#ifdef ISBOOT_USE_CRC32C_TABLE
#if 0
	/* initialize by isboot_start() */
	if (!isboot_crc32c_initialized) {
		isboot_init_crc32c_table();
	}
#endif
#else
	reflect_polynomial = isboot_reflect(isboot_crc32c_polynomial, 32);
#endif /* ISBOOT_USE_CRC32C_TABLE */

	for (s = 0; s < len; s++) {
#ifdef ISBOOT_USE_CRC32C_TABLE
		crc = (crc >> 8) ^ isboot_crc32c_table[(crc ^ buf[s]) & 0xff];
#else
		val = buf[s];
		for (i = 0; i < 8; i++) {
			if ((crc ^ val) & 1) {
				crc = (crc >> 1) ^ reflect_polynomial;
			} else {
				crc = (crc >> 1);
			}
			val = val >> 1;
		}
#endif /* ISBOOT_USE_CRC32C_TABLE */
	}
	return (crc);
}

uint32_t
isboot_fixup_crc32c(size_t total, uint32_t crc)
{
	uint8_t padding[ISCSI_ALIGNMENT];
	size_t pad_length;
	size_t rest;

	if (total == 0)
		return (crc);
#if 0
	/* alignment must be power of 2 */
	rest = total & ~(ISCSI_ALIGNMENT - 1);
#endif
	rest = total % ISCSI_ALIGNMENT;
	if (rest != 0) {
		pad_length = ISCSI_ALIGNMENT;
		pad_length -= rest;
		if (pad_length > 0 && pad_length < sizeof padding){
			memset(padding, 0, sizeof padding);
			crc = isboot_update_crc32c(padding, pad_length, crc);
		}
	}
	return (crc);
}

uint32_t
isboot_crc32c(const uint8_t *buf, size_t len)
{
	uint32_t crc32c;

	crc32c = isboot_crc32c_initial;
	crc32c = isboot_update_crc32c(buf, len, crc32c);
	if ((len % ISCSI_ALIGNMENT) != 0) {
		crc32c = isboot_fixup_crc32c(len, crc32c);
	}
	crc32c = crc32c ^ isboot_crc32c_xor;
	return (crc32c);
}

uint32_t
isboot_iovec_crc32c(const struct iovec *iovp, int iovc, uint32_t offset, uint32_t len)
{
	const uint8_t *p;
	uint32_t total;
	uint32_t pos;
	uint32_t n;
	uint32_t crc32c;
	int i;

	pos = 0;
	total = 0;
	crc32c = isboot_crc32c_initial;
	for (i = 0; i < iovc; i++) {
		if (len == 0)
			break;
		if (pos + iovp[i].iov_len > offset) {
			p = (const uint8_t *) iovp[i].iov_base
				+ (offset - pos);
			if (iovp[i].iov_len > len) {
				n = len;
				len = 0;
			} else {
				n = iovp[i].iov_len;
				len -= n;
			}
			crc32c = isboot_update_crc32c(p, n, crc32c);
			offset += n;
			total += n;
		}
		pos += iovp[i].iov_len;
	}
#if 0
	ISBOOT_TRACE("update %d bytes\n", total);
#endif
	crc32c = isboot_fixup_crc32c(total, crc32c);
	crc32c = crc32c ^ isboot_crc32c_xor;
	return (crc32c);
}

void
isboot_dump(const char *label, const uint8_t *buf, size_t len)
{
	char tmpbuf[1024];
	char buf8[8+1];
	int total;
	int i;

	printf("%s\n", label);

	memset(buf8, 0, sizeof(buf8));
	total = 0;
	for (i = 0; i < len; i++) {
		if (i != 0 && i % 8 == 0) {
			total += snprintf(tmpbuf + total,
			    sizeof(tmpbuf) - total, "%s", buf8);
			printf("%s\n", tmpbuf);
			total = 0;
		}
		total += snprintf(tmpbuf + total, sizeof(tmpbuf) - total,
		    "%02x ", buf[i] & 0xff);
		buf8[i % 8] = isprint(buf[i]) ? buf[i] : '.';
	}
	for ( ; i % 8 != 0; i++) {
		total += snprintf(tmpbuf + total, sizeof(tmpbuf) - total,
		    "   ");
		buf8[i % 8] = ' ';
	}
	total += snprintf(tmpbuf + total, sizeof(tmpbuf) - total, "%s", buf8);
	printf("%s\n", tmpbuf);
}

#if 0
/* not used */
static int
isboot_islun2lun(uint64_t islun)
{
	uint64_t fmt_lun;
	uint64_t method;
	int lun_i;

	fmt_lun = islun;
	method = (fmt_lun >> 62) & 0x03U;
	fmt_lun = fmt_lun >> 48;
	if (method == 0x00U) {
		lun_i = (int)(fmt_lun & 0x00ffU);
	} else if (method == 0x01U) {
		lun_i = (int)(fmt_lun & 0x3fffU);
	} else {
		lun_i = 0xffffU;
	}
	return (lun_i);
}
#endif

static uint64_t
isboot_lun2islun(int lun, int maxlun)
{
	uint64_t fmt_lun;
	uint64_t method;
	uint64_t islun;

	islun = (uint64_t)lun;
	if (maxlun <= 0x0100) {
		/* below 256 */
		method = 0x00U;
		fmt_lun = (method & 0x03U) << 62;
		fmt_lun |= (islun & 0x00ffU) << 48;
	} else if (maxlun <= 0x4000U) {
		/* below 16384 */
		method = 0x01U;
		fmt_lun = (method & 0x03U) << 62;
		fmt_lun |= (islun & 0x3fffU) << 48;
	} else {
		/* XXX */
		fmt_lun = ~((uint64_t)0);
	}
	return (fmt_lun);
}

static void
isboot_gen_random(uint8_t *buf, size_t len)
{
	uint32_t r;
	int i;

	for (i = 0; i < len; i++) {
		r = arc4random();
		buf[i] = (uint8_t) r;
	}
}

static int
isboot_bin2hex(char *buf, size_t len, const uint8_t *data, size_t data_len)
{
	const char *digits = "0123456789ABCDEF";
	int total = 0;
	int i;

	if (len < 3)
		return (-1);
	buf[total] = '0';
	total++;
	buf[total] = 'x';
	total++;
	buf[total] = '\0';

	for (i = 0; i < data_len; i++) {
		if (total + 3 > len) {
			buf[total] = '\0';
			return (-1);
		}
		buf[total] = digits[(data[i] >> 4) & 0x0fU];
		total++;
		buf[total] = digits[data[i] & 0x0fU];
		total++;
	}
	buf[total] = '\0';
	return (total);
}

static int
isboot_hex2bin(uint8_t *data, size_t data_len, const char *str)
{
	const char *digits = "0123456789ABCDEF";
	const char *dp;
	const char *p;
	int total = 0;
	int n0, n1;

	p = str;
	if (p[0] != '0' && (p[1] != 'x' && p[1] != 'X'))
		return (-1);
	p += 2;

	while (p[0] != '\0' && p[1] != '\0') {
		if (total >= data_len) {
			return (-1);
		}
		dp = strchr(digits, toupper((int) p[0]));
		if (dp == NULL) {
			return (-1);
		}
		n0 = (int) (dp - digits);
		dp = strchr(digits, toupper((int) p[1]));
		if (dp == NULL) {
			return (-1);
		}
		n1 = (int) (dp - digits);

		data[total] = (uint8_t) (((n0 & 0x0fU) << 4) | (n1 & 0x0fU));
		total++;
		p += 2;
	}
	return (total);
}

static int
isboot_b642bin(uint8_t *data, size_t data_len, const char *str)
{
	const char *digits =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
	const char *dp;
	const char *p;
	int total = 0;
	int n0, n1, n2, n3;

	p = str;
	if (p[0] != '0' && (p[1] != 'b' && p[1] != 'b'))
		return (-1);
	p += 2;

	while (p[0] != '\0' && p[1] != '\0') {
		if (total >= data_len) {
			return (-1);
		}
		dp = strchr(digits, (int) p[0]);
		if (dp == NULL) {
			return (-1);
		}
		n0 = (int) (dp - digits);
		dp = strchr(digits, (int) p[1]);
		if (dp == NULL) {
			return (-1);
		}
		n1 = (int) (dp - digits);
		if (p[2] != '=') {
			dp = strchr(digits, (int) p[2]);
			if (dp == NULL) {
				return (-1);
			}
			n2 = (int) (dp - digits);
		} else {
			n2 = -1;
		}
		if (p[3] != '=') {
			dp = strchr(digits, (int) p[3]);
			if (dp == NULL) {
				return (-1);
			}
			n3 = (int) (dp - digits);
		} else {
			n3 = -1;
		}

		data[total] = ((n0 & 0x3fU) << 2) | ((n1 & 0x30U) >> 4);
		total++;
		if (n2 >= 0) {
			data[total]
				= ((n1 & 0x0fU) << 4) | ((n2 & 0x3cU) >> 2);
			total++;
		}
		if (n3 >= 0) {
			data[total]
				= ((n2 & 0x03U) << 6) | ((n3 & 0x3fU) >> 0);
			total++;
		}
		if (n2 < 0 || n3 < 0)
			break;
		p += 4;
	}
	return (total);
}

static int
isboot_str2bin(uint8_t *data, size_t data_len, const char *str)
{
	const char *p;
	int total = 0;

	p = str;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		total = isboot_hex2bin(data, data_len, str);
	else if (p[0] == '0' && (p[1] == 'b' && p[1] == 'B'))
		total = isboot_b642bin(data, data_len, str);
	else {
		ISBOOT_ERROR("str2bin format error\n");
		total = -1;
	}
	return (total);
}

static int
isboot_append_param(pdu_t *pp, char *format, ...)
{
	va_list ap;
	int n;

	va_start(ap, format);
	n = vsnprintf((char *)pp->ds_addr + pp->ds_len,
	    pp->ds_size - pp->ds_len - 1, format, ap);
	va_end(ap);
	pp->ds_len += n;
	if (n > 0) {
		/* NUL separated strings */
		pp->ds_len++;
	} else {
		/* XXX */
		ISBOOT_ERROR("append error\n");
	}
	return (n);
}


// changed in r324446
#if __FreeBSD_version >= 1200051
static void
isboot_free_mbufext(struct mbuf *m)
#else
static void
isboot_free_mbufext(struct mbuf *m, void *p, void *optarg)
#endif
{
#if __FreeBSD_version >= 1200051
	void *p = m->m_ext.ext_buf;
#endif

	ISBOOT_TRACE("isboot_free_mbufext\n");
	if (p == NULL)
		return;
	isboot_free_mext(p);
}

static int
isboot_xmit_pdu(struct isboot_sess *sess, pdu_t *pp)
{
	struct mbuf *mh, *md;
	uint8_t *bhs;
	uint8_t *ds_dd;
	uint32_t crc32c;
	int error;

	/* BHS + AHS + HD */
	if (ISCSI_BHS_LEN + ISCSI_ALIGN(pp->ahs_len)
	    + sizeof(pp->hdr_dig) > MHLEN) {
		panic("AHS=%d is too large", pp->ahs_len);
	}
	MGETHDR(mh, M_NOWAIT, MT_DATA);
	if (mh == NULL)
		panic("no mbuf memory");
	mh->m_pkthdr.rcvif = NULL;
	memcpy(mh->m_data, &pp->ipdu.bhs, ISCSI_BHS_LEN);
	mh->m_len = ISCSI_BHS_LEN;
	if (pp->ahs_len != 0) {
		memcpy(mh->m_data + mh->m_len, pp->ahs_addr, pp->ahs_len);
		mh->m_len += pp->ahs_len;
		if ((ISCSI_ALIGN(pp->ahs_len) - pp->ahs_len) != 0) {
			memset(mh->m_data + mh->m_len, 0,
			    ISCSI_ALIGN(pp->ahs_len) - pp->ahs_len);
			mh->m_len += ISCSI_ALIGN(pp->ahs_len) - pp->ahs_len;
		}
	}
	if (sess->header_digest != 0) {
		crc32c = isboot_crc32c(mh->m_data, mh->m_len);
		MAKE_DIGEST_WORD(&pp->hdr_dig, crc32c);
		memcpy(mh->m_data + mh->m_len, &pp->hdr_dig,
		    sizeof(pp->hdr_dig));
		mh->m_len += sizeof(pp->hdr_dig);
	}
	mh->m_pkthdr.len = mh->m_len;

	/* DATA + DD */
	if (pp->ds_len != 0) {
		/* allocate external buffer and add it to mbuf */
		ds_dd = isboot_malloc_mext(ISCSI_ALIGN(pp->ds_len)
		    + sizeof(pp->ds_dig));
		MGET(md, M_NOWAIT, MT_DATA);
		if (mh == NULL)
			panic("no mbuf memory");
		MEXTADD(md, (caddr_t)ds_dd, (ISCSI_ALIGN(pp->ds_len)
			+ sizeof(pp->ds_dig)),
		    isboot_free_mbufext, ds_dd, NULL, 0, EXT_MOD_TYPE);
		memcpy(md->m_data, pp->ds_addr, pp->ds_len);
		md->m_len = pp->ds_len;
		if ((ISCSI_ALIGN(pp->ds_len) - pp->ds_len) != 0) {
			memset(md->m_data + md->m_len, 0,
			    ISCSI_ALIGN(pp->ds_len) - pp->ds_len);
			md->m_len += ISCSI_ALIGN(pp->ds_len) - pp->ds_len;
		}
		if (sess->data_digest != 0 && pp->ds_len != 0) {
			crc32c = isboot_crc32c(md->m_data, md->m_len);
			MAKE_DIGEST_WORD(&pp->ds_dig, crc32c);
			memcpy(md->m_data + md->m_len, &pp->ds_dig,
			    sizeof(pp->ds_dig));
			md->m_len += sizeof(pp->ds_dig);
		}
	} else {
		md = NULL;
	}
	mh->m_next = md;

	/* set data segment size in BHS */
	bhs = (uint8_t *)mh->m_data;
	DSET8(&bhs[4], ISCSI_ALIGN(pp->ahs_len) / 4);
	DSET24(&bhs[5], pp->ds_len);

	/* send mbuf chain */
	if (sess->so == NULL) {
		/* should not happen */
		ISBOOT_TRACE("so=NULL\n");
		return (ENXIO);
	}
	error = sosend(sess->so, NULL, NULL, mh, NULL, 0, sess->td);
	if (error) {
		ISBOOT_ERROR("sosend error %d\n", error);
		return (error);
	}
	return (0);
}

static int
isboot_recv_pdu(struct isboot_sess *sess, pdu_t *pp)
{
	struct mbuf *mp;
	struct uio uio;
	uint8_t *bhs;
	uint32_t crc32c;
	uint32_t total;
	int error;
	int flags;
	int ahs_len, ds_len;

	memset(&uio, 0, sizeof(uio));
	total = 0;

	/* BHS */
	flags = MSG_WAITALL;
	uio.uio_resid = ISCSI_BHS_LEN;
	error = soreceive(sess->so, NULL, &uio, &mp, NULL, &flags);
	if (error) {
		ISBOOT_ERROR("soreceive BHS error %d\n", error);
		return (error);
	}
	if (uio.uio_resid != 0) {
		ISBOOT_ERROR("soreceive BHS is not complete\n");
		return (EIO);
	}
	m_copydata(mp, 0, ISCSI_BHS_LEN, (caddr_t)&pp->ipdu.bhs);
	m_freem(mp);
	total += ISCSI_BHS_LEN;
	bhs = (uint8_t *)&pp->ipdu.bhs;
	ahs_len = DGET8(&bhs[4]);
	ahs_len *= 4;
	ds_len = DGET24(&bhs[5]);

	/* prepare memory for pdu_t */
	if (pp->ahs_size < ISCSI_ALIGN(ahs_len)) {
		if (pp->ahs_size != 0)
			isboot_free_pdubuf(pp->ahs_addr);
		pp->ahs_size = ISCSI_ALIGN(ahs_len);
		pp->ahs_addr = isboot_malloc_pdubuf(pp->ahs_size);
		if (pp->ahs_addr == NULL) {
			ISBOOT_ERROR("malloc error\n");
			return (ENOMEM);
		}
	}
	if (pp->ds_size < ISCSI_ALIGN(ds_len)) {
		if (pp->ds_size != 0)
			isboot_free_pdubuf(pp->ds_addr);
		pp->ds_size = ISCSI_ALIGN(ds_len);
		pp->ds_addr = isboot_malloc_pdubuf(pp->ds_size);
		if (pp->ds_addr == NULL) {
			ISBOOT_ERROR("malloc error\n");
			return (ENOMEM);
		}
	}

	/* AHS */
	if (ahs_len != 0) {
		flags = MSG_WAITALL;
		uio.uio_resid = ISCSI_ALIGN(ahs_len);
		error = soreceive(sess->so, NULL, &uio, &mp, NULL, &flags);
		if (error) {
			ISBOOT_ERROR("soreceive AHS error %d\n", error);
			return (error);
		}
		if (uio.uio_resid != 0) {
			ISBOOT_ERROR("soreceive AHS is not complete\n");
			return (EIO);
		}
		m_copydata(mp, 0, ISCSI_ALIGN(ahs_len),
		    (caddr_t)pp->ahs_addr);
		m_freem(mp);
		pp->ahs_len = ahs_len;
		total += ISCSI_ALIGN(ahs_len);
	}

	/* HD */
	if (sess->header_digest != 0) {
		flags = MSG_WAITALL;
		uio.uio_resid = sizeof(pp->hdr_dig);
		error = soreceive(sess->so, NULL, &uio, &mp, NULL, &flags);
		if (error) {
			ISBOOT_ERROR("soreceive HD error %d\n", error);
			return (error);
		}
		if (uio.uio_resid != 0) {
			ISBOOT_ERROR("soreceive HD is not complete\n");
			return (EIO);
		}
		m_copydata(mp, 0, sizeof(pp->hdr_dig),
		    (caddr_t)&pp->hdr_dig);
		m_freem(mp);
		total += sizeof(pp->hdr_dig);
	}

	/* DATA */
	if (ds_len != 0) {
		flags = MSG_WAITALL;
		uio.uio_resid = ISCSI_ALIGN(ds_len);
		error = soreceive(sess->so, NULL, &uio, &mp, NULL, &flags);
		if (error) {
			ISBOOT_ERROR("soreceive DATA error %d\n", error);
			return (error);
		}
		if (uio.uio_resid != 0) {
			ISBOOT_ERROR("soreceive DATA is not complete\n");
			return (EIO);
		}
		m_copydata(mp, 0, ISCSI_ALIGN(ds_len),
		    (caddr_t)pp->ds_addr);
		m_freem(mp);
		pp->ds_len = ds_len;
		total += ISCSI_ALIGN(ds_len);
	}

	/* DD */
	if (sess->data_digest != 0 && ds_len != 0) {
		flags = MSG_WAITALL;
		uio.uio_resid = sizeof(pp->ds_dig);
		error = soreceive(sess->so, NULL, &uio, &mp, NULL, &flags);
		if (error) {
			ISBOOT_ERROR("soreceive DD error %d\n", error);
			return (error);
		}
		if (uio.uio_resid != 0) {
			ISBOOT_ERROR("soreceive DD is not complete\n");
			return (EIO);
		}
		m_copydata(mp, 0, sizeof(pp->ds_dig),
		    (caddr_t)&pp->ds_dig);
		m_freem(mp);
		total += sizeof(pp->ds_dig);
	}

	/* check digest */
	if (sess->header_digest != 0) {
		if (pp->ahs_len == 0) {
			crc32c = isboot_crc32c((uint8_t *)&pp->ipdu.bhs,
			    ISCSI_BHS_LEN);
		} else {
			int upd_total = 0;
			crc32c = isboot_crc32c_initial;
			crc32c = isboot_update_crc32c((uint8_t *)&pp->ipdu.bhs,
			    ISCSI_BHS_LEN, crc32c);
			upd_total += ISCSI_BHS_LEN;
			crc32c = isboot_update_crc32c((uint8_t *)pp->ahs_addr,
			    pp->ahs_len, crc32c);
			upd_total += pp->ahs_len;
			crc32c = isboot_fixup_crc32c(upd_total, crc32c);
			crc32c = crc32c ^ isboot_crc32c_xor;
		}
		if (MATCH_DIGEST_WORD(&pp->hdr_dig, crc32c) == 0) {
			ISBOOT_ERROR("header digest error\n");
			return (EIO);
		}
	}
	if (sess->data_digest != 0 && ds_len != 0) {
		crc32c = isboot_crc32c(pp->ds_addr, ds_len);
		if (MATCH_DIGEST_WORD(&pp->ds_dig, crc32c) == 0) {
			ISBOOT_ERROR("data digest error\n");
			return (EIO);
		}
	}

	return (0);
}

static void
isboot_free_pdu(pdu_t *pp)
{

	if (pp == NULL)
		return;
	if (pp->ahs_size != 0)
		isboot_free_pdubuf(pp->ahs_addr);
	if (pp->ds_size != 0)
		isboot_free_pdubuf(pp->ds_addr);
	memset(&pp->ipdu.bhs, 0, sizeof(pp->ipdu.bhs));
	pp->ahs_addr = NULL;
	pp->ds_addr = NULL;
	pp->ahs_size = 0;
	pp->ahs_len = 0;
	pp->ds_size = 0;
	pp->ds_len = 0;
}

static int
isboot_update_option(struct isboot_sess *sess, pdu_t *pp)
{
	char *kp, *vp, *last;
	char *p, *q, *np;

	p = (char *)pp->ds_addr;
	last = (char *)pp->ds_addr + pp->ds_len;
	while (p < last && *p != '\0') {
		/* kp = "KEY=VAL<NUL>", vp = "VAL<NUL>" */
		for (kp = q = p; q < last && *q != '\0' && *q != '='; q++)
			;
		if (q >= last || *q == '\0') {
			ISBOOT_ERROR("parse error (kp=%.64s)\n", kp);
			return (EINVAL);
		}
		*q++ = '\0';
		np = vp = q;
		ISBOOT_TRACE("KEY=[%s], VAL=[%s]\n", kp, vp);
		if (strcasecmp(vp, "Reject") == 0 ||
		    strcasecmp(vp, "Irrelevant") == 0 ||
		    strcasecmp(vp, "NotUnderstood") == 0) {
			/* skip this values's key */
		} else if (strcasecmp(kp, "TargetAddress") == 0) {
			isboot_free_str(sess->opt.targetAddress);
			q = sess->opt.targetAddress = isboot_strdup(vp);
			/* [xx:xx::xx]:yy,zz or x.x.x.x:yy,zz */
			if (*vp == '[') {
				while (*q != '\0' && *q != ']')
					q++;
				if (*q == '\0') {
					ISBOOT_ERROR("parse error (kp=%.64s, vp=%.64s)\n",
					    kp, vp);
					return (EINVAL);
				}
				if (*q == ']')
					*++q = '\0';
			}
			while (*q != '\0' && *q != ':')
				q++;
			if (*q == ':')
				sess->opt.port = (int)strtol(q + 1, NULL, 10);
			q = vp;
			while (*q != '\0' && *q != ',')
				q++;
			if (*q == ',')
				sess->opt.targetPortalGroupTag
					= (int)strtol(q + 1, NULL, 10);
		} else if (strcasecmp(kp, "HeaderDigest") == 0) {
			isboot_free_str(sess->opt.headerDigest);
			sess->opt.headerDigest = isboot_strdup(vp);
		} else if (strcasecmp(kp, "DataDigest") == 0) {
			isboot_free_str(sess->opt.dataDigest);
			sess->opt.dataDigest = isboot_strdup(vp);
		} else if (strcasecmp(kp, "MaxConnections") == 0) {
			sess->opt.maxConnections
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "TargetPortalGroupTag") == 0) {
			sess->opt.targetPortalGroupTag
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "InitialR2T") == 0) {
			sess->opt.initialR2T
				= (strcasecmp(vp, "Yes") == 0) ? TRUE : FALSE;
		} else if (strcasecmp(kp, "ImmediateData") == 0) {
			sess->opt.immediateData
				= (strcasecmp(vp, "Yes") == 0) ? TRUE : FALSE;
		} else if (strcasecmp(kp, "MaxRecvDataSegmentLength") == 0) {
			sess->opt.maxXmitDataSegmentLength
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "MaxBurstLength") == 0) {
			sess->opt.maxBurstLength
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "FirstBurstLength") == 0) {
			sess->opt.firstBurstLength
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "DefaultTime2Wait") == 0) {
			sess->opt.defaultTime2Wait
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "DefaultTime2Retain") == 0) {
			sess->opt.defaultTime2Retain
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "MaxOutstandingR2T") == 0) {
			sess->opt.maxOutstandingR2T
				= (int)strtol(vp, NULL, 10);
		} else if (strcasecmp(kp, "DataPDUInOrder") == 0) {
			sess->opt.dataPDUInOrder
				= (strcasecmp(vp, "Yes") == 0) ? TRUE : FALSE;
		} else if (strcasecmp(kp, "DataSequenceInOrder") == 0) {
			sess->opt.dataSequenceInOrder
				= (strcasecmp(vp, "Yes") == 0) ? TRUE : FALSE;
		} else if (strcasecmp(kp, "ErrorRecoveryLevel") == 0) {
			sess->opt.errorRecoveryLevel
				= (int)strtol(vp, NULL, 10);
		}

		while (np < last && *np != '\0')
			np++;
		p = np + 1;
	}
	return (0);
}

static int
isboot_update_security(struct isboot_sess *sess, pdu_t *pp)
{
	char *kp, *vp, *last;
	char *p, *q, *np;
	int len;

	p = (char *)pp->ds_addr;
	last = (char *)pp->ds_addr + pp->ds_len;
	while (p < last && *p != '\0') {
		/* kp = "KEY=VAL<NUL>", vp = "VAL<NUL>" */
		for (kp = q = p; q < last && *q != '\0' && *q != '='; q++)
			;
		if (q >= last || *q == '\0') {
			ISBOOT_ERROR("parse error (kp=%.64s)\n", kp);
			return (EINVAL);
		}
		*q++ = '\0';
		np = vp = q;
		ISBOOT_TRACE("KEY=[%s], VAL=[%s]\n", kp, vp);
		if (strcasecmp(vp, "Reject") == 0 ||
		    strcasecmp(vp, "Irrelevant") == 0 ||
		    strcasecmp(vp, "NotUnderstood") == 0) {
			/* skip this values's key */
		} else if (strcasecmp(kp, "AuthMethod") == 0) {
			isboot_free_str(sess->opt.authMethod);
			sess->opt.authMethod = isboot_strdup(vp);
		} else if (strcasecmp(kp, "CHAP_A") == 0) {
			isboot_free_str(sess->auth.algorithm);
			sess->auth.algorithm = isboot_strdup(vp);
		} else if (strcasecmp(kp, "CHAP_I") == 0) {
			sess->auth.chap_id[0] = (uint8_t)strtol(vp, NULL, 0);
		} else if (strcasecmp(kp, "CHAP_C") == 0) {
			len = isboot_str2bin(sess->auth.chap_challenge,
			    ISBOOT_CHAP_CHALLENGE_LEN, vp);
			if (len < 0) {
				ISBOOT_ERROR("challenge format error\n");
				return (EINVAL);
			}
			sess->auth.chap_challenge_len = len;
		} else if (strcasecmp(kp, "CHAP_N") == 0) {
			strlcpy(sess->auth.chap_muser, vp,
			    sizeof(sess->auth.chap_muser));
		} else if (strcasecmp(kp, "CHAP_R") == 0) {
			strlcpy(sess->auth.chap_mresponse_string, vp,
			    sizeof(sess->auth.chap_mresponse_string));
			len = isboot_str2bin(sess->auth.chap_mresponse,
			    sizeof(sess->auth.chap_mresponse),
			    sess->auth.chap_mresponse_string);
			if (len < 0) {
				ISBOOT_ERROR("response format error\n");
				return (EINVAL);
			}
			sess->auth.chap_mresponse_len = len;
		}

		while (np < last && *np != '\0')
			np++;
		p = np + 1;
	}
	return (0);
}

static void
isboot_get_chap_response(struct isboot_sess *sess)
{
	MD5_CTX md5ctx;

	MD5Init(&md5ctx);
	/* identifier */
	MD5Update(&md5ctx, sess->auth.chap_id, 1);
	/* secret */
	MD5Update(&md5ctx, sess->auth.secret, strlen(sess->auth.secret));
	/* challenge */
	MD5Update(&md5ctx, sess->auth.chap_challenge,
	    sess->auth.chap_challenge_len);
	/* response */
	MD5Final(sess->auth.chap_response, &md5ctx);
	sess->auth.chap_response_len = MD5_DIGEST_LENGTH;

	/* convert to string */
	isboot_bin2hex(sess->auth.chap_response_string,
	    sizeof(sess->auth.chap_response_string), sess->auth.chap_response,
	    sess->auth.chap_response_len);
}

static int
isboot_compare_chap_mresponse(struct isboot_sess *sess)
{
	MD5_CTX md5ctx;
	uint8_t ini_digest[MD5_DIGEST_LENGTH];
	int ini_digest_len;

	MD5Init(&md5ctx);
	/* identifier */
	MD5Update(&md5ctx, sess->auth.chap_mid, 1);
	/* secret */
	MD5Update(&md5ctx, sess->auth.msecret, strlen(sess->auth.msecret));
	/* challenge */
	MD5Update(&md5ctx, sess->auth.chap_mchallenge,
	    sess->auth.chap_mchallenge_len);
	/* response */
	MD5Final(ini_digest, &md5ctx);
	ini_digest_len = MD5_DIGEST_LENGTH;

	if (sess->auth.chap_mresponse_len < 0 ||
	    sess->auth.chap_mresponse_len != ini_digest_len)
		return (-1);
	return memcmp(ini_digest, sess->auth.chap_mresponse, ini_digest_len);
}

static int
isboot_rsp_login(struct isboot_sess *sess, pdu_t *pp)
{
	uint8_t *rsp = (uint8_t *)&pp->ipdu.bhs;
	uint32_t ExpCmdSN, MaxCmdSN;
	uint16_t tsih;
	int T_bit;
	int CSG, NSG;
	int StatusClass, StatusDetail;
	int error;

	if (rsp[0] == ISCSI_OP_REJECT) {
		ISBOOT_ERROR("cmd was rejected\n");
		return (EIO);
	}
	if (rsp[0] != ISCSI_OP_LOGIN_RSP) {
		ISBOOT_ERROR("cmd is not login response\n");
		return (EIO);
	}
	if (DGET32(&rsp[16]) != sess->itt) {
		ISBOOT_ERROR("initiator task tag error\n");
		return (EIO);
	}

	T_bit = BGET8(&rsp[1], 7);
	CSG = BGET8W(&rsp[1], 3, 2);
        NSG = BGET8W(&rsp[1], 1, 2);
	tsih = DGET16(&rsp[14]);

	ExpCmdSN = DGET32(&rsp[28]);
	MaxCmdSN = DGET32(&rsp[32]);
	sess->cws = MaxCmdSN - ExpCmdSN + 1;
	if (sess->cws > sess->opt.tags && sess->cws <= ISBOOT_CAM_MAX_TAGS)
		sess->opt.tags = sess->cws;

	/* RFC3720 10.13.5 */
	StatusClass  = rsp[36];
	StatusDetail = rsp[37];
	error = -1;
	switch (StatusClass) {
	case 0:
		/* Success */
		if (sess->stage == ISBOOT_SECURITYNEGOTIATION) {
			if (sess->chap_stage == ISBOOT_CHAP_MUTUAL) {
				if (isboot_compare_chap_mresponse(sess) != 0) {
					ISBOOT_ERROR("CHAP error\n");
					error = -1;
					break;
				}
				sess->chap_stage = ISBOOT_CHAP_END;
				sess->authenticated = 1;
			} else if (sess->chap_stage == ISBOOT_CHAP_END) {
				if (T_bit != 0)
					sess->authenticated = 1;
			}
		}

		if (T_bit != 0) {
			if (sess->authenticated == 0) {
				ISBOOT_ERROR("Authentication is not passed\n");
				error = -1;
				break;
			}
			sess->stage = NSG;
			if (sess->stage == ISBOOT_FULLFEATUREPHASE) {
				sess->tsih = tsih;
				if (sess->tsih == 0) {
					ISBOOT_ERROR("invalid tsih\n");
					break;
				}
				sess->full_feature = 1;
			}
		}
		error = 0;
		break;
	case 1:
		/* Redirection */
		ISBOOT_ERROR("Login failed: 0x%04x\n",
		    (StatusClass << 8) | StatusDetail);
		break;
	case 2:
		/* Initiator Error */
		ISBOOT_ERROR("Login failed: 0x%04x\n",
		    (StatusClass << 8) | StatusDetail);
		break;
	case 3:
		/* Target Error */
		ISBOOT_ERROR("Login failed: 0x%04x\n",
		    (StatusClass << 8) | StatusDetail);
		break;
	default:
		/* unknown */
		ISBOOT_ERROR("Login failed: 0x%04x\n",
		    (StatusClass << 8) | StatusDetail);
		break;
	}
	return (error);
}

static int
isboot_do_login(struct isboot_sess *sess)
{
	pdu_t pdu, *pp;
	uint8_t *req;
	static int I_bit = 1;
	int T_bit, C_bit;
	int CSG, NSG;
	int error;
	int xcnt;

	ISBOOT_TRACE("login start\n");
	sess->chap_stage = ISBOOT_CHAP_NONE;
	if (sess->req_auth != 0) {
		/* deal with CHAP */
		sess->authenticated = 0;
		sess->stage = ISBOOT_SECURITYNEGOTIATION;
		sess->auth.chap_id[0] = 0;
		sess->auth.chap_mid[0] = 0;
		sess->auth.chap_challenge_len = -1;
		sess->auth.chap_mchallenge_len = -1;
		memset(sess->auth.chap_muser, 0,
		    sizeof(sess->auth.chap_muser));
		memset(sess->auth.chap_mresponse_string, 0,
		    sizeof(sess->auth.chap_mresponse_string));
		sess->auth.chap_mresponse_len = -1;
	} else {
		/* no authentication */
		sess->authenticated = 1;
		sess->stage = ISBOOT_LOGINOPERATIONALNEGOTIATION;
	}

	xcnt = 0;
next_loginpdu:
	pp = &pdu;
	req = (uint8_t *)&pdu.ipdu.bhs;
	memset(req, 0, ISCSI_BHS_LEN);
	req[0] = ISCSI_OP_LOGIN_REQ;
	/* Flip I bit each time as a cheap way to toggle between Login
	 * and Login (retry). Some targets (eg ctld) do not handle
	 * the later */
	I_bit ^= 1;
	T_bit = C_bit = 0;
	CSG = NSG = 0;
	BDADD8(&req[0], I_bit, 7);
	BDADD8(&req[1], T_bit, 7);
	BDADD8(&req[1], C_bit, 6);
	BDADD8W(&req[1], CSG, 3, 2);
	BDADD8W(&req[1], NSG, 1, 2);
	req[2] = 0x00; /* RFC3720 10.12.4 */
	req[3] = 0x00;
	DSET48(&req[8], sess->isid);
	DSET16(&req[14], sess->tsih);
	DSET16(&req[20], sess->cid);
	DSET32(&req[16], sess->itt);
	mtx_lock_spin(&sess->sn_mtx);
	DSET32(&req[24], sess->cmdsn);
	DSET32(&req[28], sess->statsn);
	mtx_unlock_spin(&sess->sn_mtx);

	pp->ahs_size = 0;
	pp->ahs_len = 0;
	pp->ahs_addr = NULL;
	pp->ds_size = sess->opt.maxXmitDataSegmentLength;
	pp->ds_len = 0;
	pp->ds_addr = isboot_malloc_pdubuf(pp->ds_size);
	if (pp->ds_addr == NULL)
		return (ENOMEM);

	switch (sess->stage) {
	case ISBOOT_SECURITYNEGOTIATION:
		CSG = ISBOOT_SECURITYNEGOTIATION;
		NSG = ISBOOT_LOGINOPERATIONALNEGOTIATION;
		T_bit = 0;
		break;
	case ISBOOT_LOGINOPERATIONALNEGOTIATION:
		CSG = ISBOOT_LOGINOPERATIONALNEGOTIATION;
		NSG = ISBOOT_FULLFEATUREPHASE;
		T_bit = 1;
		break;
	default:
		ISBOOT_ERROR("stage error(%d)\n", sess->stage);
		isboot_free_pdu(pp);
		return (EOPNOTSUPP);
	}
	BDADD8(&req[1], T_bit, 7);
	BDADD8W(&req[1], CSG, 3, 2);
	BDADD8W(&req[1], NSG, 1, 2);

	if (sess->tsih == 0 && sess->chap_stage == ISBOOT_CHAP_NONE) {
		/* leading connection */
		isboot_append_param(pp, "InitiatorName=%s",
		    sess->initiator_name);
		if (sess->discovery != 0) {
			isboot_append_param(pp, "SessionType=%s",
			    "Discovery");
		} else {
			isboot_append_param(pp, "SessionType=%s",
			    "Normal");
			isboot_append_param(pp, "TargetName=%s",
			    sess->target_name);
		}
	}
	switch (sess->stage) {
	case ISBOOT_SECURITYNEGOTIATION:
		switch(sess->chap_stage) {
		case ISBOOT_CHAP_NONE:
			isboot_append_param(pp, "AuthMethod=%s",
			    sess->opt.authMethod);
			sess->chap_stage = ISBOOT_CHAP_WAIT_A;
			break;
		case ISBOOT_CHAP_WAIT_A:
			if (strcasecmp(sess->opt.authMethod, "CHAP") != 0) {
				ISBOOT_ERROR("Can't handle method=%s\n",
				    sess->opt.authMethod);
				isboot_free_pdu(pp);
				return (EOPNOTSUPP);
			}
			isboot_append_param(pp, "CHAP_A=%s",
			    "5");	/* MD5 */
			sess->chap_stage = ISBOOT_CHAP_WAIT_NR;
			break;
		case ISBOOT_CHAP_WAIT_NR:
			if (sess->auth.chap_challenge_len < 0) {
				ISBOOT_ERROR("Can't handle method=%s\n",
				    sess->opt.authMethod);
				isboot_free_pdu(pp);
				return (EOPNOTSUPP);
			}
			isboot_get_chap_response(sess);
			isboot_append_param(pp, "CHAP_N=%s",
			    sess->auth.user);
			isboot_append_param(pp, "CHAP_R=%s",
			    sess->auth.chap_response_string);
			if (sess->req_mutual != 0) {
				isboot_gen_random(sess->auth.chap_mid, 1);
				sess->auth.chap_mchallenge_len
				    = sess->auth.chap_challenge_len;
				isboot_gen_random(sess->auth.chap_mchallenge,
				    sess->auth.chap_mchallenge_len);
				isboot_bin2hex(
				    sess->auth.chap_mchallenge_string,
				    sizeof(sess->auth.chap_mchallenge_string),
				    sess->auth.chap_mchallenge,
				    sess->auth.chap_mchallenge_len);
				isboot_append_param(pp, "CHAP_I=%d",
				    sess->auth.chap_mid[0]);
				isboot_append_param(pp, "CHAP_C=%s",
				    sess->auth.chap_mchallenge_string);
				sess->chap_stage = ISBOOT_CHAP_MUTUAL;
			} else {
				sess->chap_stage = ISBOOT_CHAP_END;
			}
			T_bit = 1;
			BDADD8(&req[1], T_bit, 7);
			break;
		default:
			sess->chap_stage = ISBOOT_CHAP_NONE;
			ISBOOT_ERROR("CHAP stage error(%d)\n",
			    sess->chap_stage);
			isboot_free_pdu(pp);
			return (EOPNOTSUPP);
		}
		break;
	case ISBOOT_LOGINOPERATIONALNEGOTIATION:
		isboot_append_param(pp, "HeaderDigest=%s",
		    sess->opt.headerDigest);
		isboot_append_param(pp, "DataDigest=%s",
		    sess->opt.dataDigest);
		isboot_append_param(pp, "MaxRecvDataSegmentLength=%d",
		    sess->opt.maxRecvDataSegmentLength);
		isboot_append_param(pp, "DefaultTime2Wait=%d",
		    sess->opt.defaultTime2Wait);
		isboot_append_param(pp, "DefaultTime2Retain=%d",
		    sess->opt.defaultTime2Retain);
		isboot_append_param(pp, "ErrorRecoveryLevel=%d",
		    sess->opt.errorRecoveryLevel);

		if (sess->discovery == 0) {
			isboot_append_param(pp, "MaxConnections=%d",
			    sess->opt.maxConnections);
			isboot_append_param(pp, "InitialR2T=%s",
			    sess->opt.initialR2T ? "Yes" : "No");
			isboot_append_param(pp, "ImmediateData=%s",
			    sess->opt.immediateData ? "Yes" : "No");
			isboot_append_param(pp, "MaxBurstLength=%d",
			    sess->opt.maxBurstLength);
			isboot_append_param(pp, "MaxOutstandingR2T=%d",
			    sess->opt.maxOutstandingR2T);
			isboot_append_param(pp, "DataPDUInOrder=%s",
			    sess->opt.dataPDUInOrder ? "Yes" : "No");
			isboot_append_param(pp, "DataSequenceInOrder=%s",
			    sess->opt.dataSequenceInOrder ? "Yes" : "No");
			if (!sess->opt.initialR2T ||
			    sess->opt.immediateData) {
				isboot_append_param(pp, "FirstBurstLength=%d",
				    sess->opt.firstBurstLength);
			}
		}
		break;
	default:
		ISBOOT_ERROR("stage error(%d)\n", sess->stage);
		isboot_free_pdu(pp);
		return (EOPNOTSUPP);
	}

	ISBOOT_TRACE("xmit PDU\n");
	error = isboot_xmit_pdu(sess, pp);
	if (error) {
		isboot_free_pdu(pp);
		return (error);
	}
	ISBOOT_TRACE("recv PDU\n");
	error = isboot_recv_pdu(sess, pp);
	if (error) {
		isboot_free_pdu(pp);
		return (error);
	}
	if (sess->stage == ISBOOT_SECURITYNEGOTIATION) {
		ISBOOT_TRACE("update security\n");
		error = isboot_update_security(sess, pp);
		if (error) {
			ISBOOT_ERROR("update security error\n");
			isboot_free_pdu(pp);
			return (error);
		}
	} else {
		ISBOOT_TRACE("update option\n");
		error = isboot_update_option(sess, pp);
		if (error) {
			ISBOOT_ERROR("update option error\n");
			isboot_free_pdu(pp);
			return (error);
		}
	}
	ISBOOT_TRACE("rsp login\n");
	error = isboot_rsp_login(sess, pp);
	if (error) {
		isboot_free_pdu(pp);
		return (error);
	}
	mtx_lock_spin(&sess->sn_mtx);
	sess->statsn++;
	mtx_unlock_spin(&sess->sn_mtx);
	ISBOOT_TRACE("free PDU\n");
	isboot_free_pdu(pp);
	if (sess->full_feature == 0) {
		xcnt++;
		if (xcnt > 10) {
			ISBOOT_ERROR("login not complete\n");
			return (EIO);
		}
		goto next_loginpdu;
	}
	/* now full feature phase */
	if (sess->full_feature != 0) {
		sess->header_digest = 0;
		if (sess->opt.headerDigest != NULL &&
		    strcasecmp(sess->opt.headerDigest, "CRC32C") == 0)
			sess->header_digest = 1;
		sess->data_digest = 0;
		if (sess->opt.dataDigest != NULL &&
		    strcasecmp(sess->opt.dataDigest, "CRC32C") == 0)
			sess->data_digest = 1;
	}
	ISBOOT_TRACE("login end\n");
	return (0);
}

static int
isboot_cam_set_devices(struct isboot_sess *sess)
{
	struct cam_path *path;
	union ccb ccb;
	int target_id;
	int lun, luns;
	int i, n;

	ISBOOT_TRACE("set devices on bus%d\n", cam_sim_path(sess->sim));
	target_id = 0;
	lun = sess->lun;
	luns = 0;
	n = 0;
	mtx_lock(&sess->cam_mtx);
	for (i = 0; i < ISBOOT_MAX_LUNS; i++) {
		if (xpt_create_path(&path, xpt_periph,
			cam_sim_path(sess->sim), target_id, i)
		    != CAM_REQ_CMP) {
			ISBOOT_ERROR("xpt create path error\n");
			continue;
		}
		memset(&ccb, 0, sizeof(ccb));
		xpt_setup_ccb(&ccb.ccb_h, path, /* priority */1);
		ccb.ccb_h.func_code = XPT_GDEVLIST;
		ccb.ccb_h.flags = CAM_DIR_NONE;
		ccb.ccb_h.retry_count = 1;
		ccb.cgdl.index = 0;
		ccb.cgdl.status = CAM_GDEVLIST_MORE_DEVS;
		while (ccb.cgdl.status == CAM_GDEVLIST_MORE_DEVS) {
			xpt_action(&ccb);
			if (ccb.ccb_h.status != CAM_REQ_CMP) {
				continue;
			}
			luns++;
			if (ccb.ccb_h.target_lun == lun) {
				if (strcasecmp(ccb.cgdl.periph_name,
					"pass") != 0) {
					snprintf(isboot_boot_device,
					    sizeof(isboot_boot_device),
					    "%s%d", ccb.cgdl.periph_name,
					    ccb.cgdl.unit_number);
				}
			}
			ISBOOT_TRACE("found device=%s%d@lun=%d\n",
			    ccb.cgdl.periph_name,
			    ccb.cgdl.unit_number,
			    (int)ccb.ccb_h.target_lun);
		}

		memset(&ccb, 0, sizeof(ccb));
		xpt_setup_ccb(&ccb.ccb_h, path, /* priority */1);
		ccb.ccb_h.func_code = XPT_REL_SIMQ;
		ccb.ccb_h.flags = CAM_DEV_QFREEZE;
		ccb.crs.release_flags = RELSIM_ADJUST_OPENINGS;
		if (sess->opt.tags > 1)
			ccb.crs.openings = sess->opt.tags - 1;
		else
			ccb.crs.openings = 1;
		xpt_action(&ccb);
		if ((ccb.ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
			ISBOOT_TRACE("XPT error\n");
		} else {
			n++;
		}
		xpt_free_path(path);
	}
	mtx_unlock(&sess->cam_mtx);
	return (luns);
}

static int
isboot_scsi_io(struct isboot_sess *sess, union ccb *ccb)
{
	struct isboot_task *taskp;
	struct ccb_scsiio *csio;
	struct ccb_hdr *ccb_h;
	uint8_t *req, *ahs;
	pdu_t pdu;
	uint64_t LUN;
	uint32_t ITT, TL;
	int immediatelen;
	int I_bit, F_bit, R_bit, W_bit, Attr_bit;
	int error;

	ISBOOT_TRACE("isboot scsi io\n");

	csio = &ccb->csio;
	ccb_h = &ccb->ccb_h;

	memset(&pdu, 0, sizeof(pdu));
	req = (uint8_t *)&pdu.ipdu.bhs;
	req[0] = ISCSI_OP_SCSI_CMD;
        I_bit = 0;
        F_bit = 1;
	R_bit = ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) ? 1 : 0;
	W_bit = ((ccb->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_OUT) ? 1 : 0;
	Attr_bit = 0;
	switch (csio->tag_action) {
	case MSG_SIMPLE_Q_TAG:	   Attr_bit = ISCSI_TASK_ATTR_SIMPLE;	break;
	case MSG_HEAD_OF_Q_TAG:    Attr_bit = ISCSI_TASK_ATTR_HOQ;	break;
	case MSG_ORDERED_Q_TAG:    Attr_bit = ISCSI_TASK_ATTR_ORDERED;	break;
	case MSG_ACA_TASK:         Attr_bit = ISCSI_TASK_ATTR_ACA;	break;
	}
	BDADD8(&req[0], I_bit, 6);
	BDADD8(&req[1], F_bit, 7);
	BDADD8(&req[1], R_bit, 6);
	BDADD8(&req[1], W_bit, 5);
	BDADD8W(&req[1], Attr_bit, 2, 3);

	LUN = isboot_lun2islun(ccb_h->target_lun, ISBOOT_MAX_LUNS);
	DSET64(&req[8], LUN);

	pdu.ahs_size = 0;
	pdu.ahs_len = 0;
	pdu.ahs_addr = NULL;
	if (csio->cdb_len > 16) {
		/* fill in BHS up to 16 bytes */
		if ((ccb_h->flags & CAM_CDB_POINTER) != 0) {
			memcpy(&req[32], csio->cdb_io.cdb_ptr, 16);
		} else {
			memcpy(&req[32], csio->cdb_io.cdb_bytes, 16);
		}
		/* AHS is multiplied by 4(32bits) */
		pdu.ahs_len = 4 + csio->cdb_len - 16;
		pdu.ahs_size = ISCSI_ALIGN(pdu.ahs_len);
		if (pdu.ahs_size > (4 * 255)) {
			/* AHS is one byte */
			panic("AHS=%d is too large", pdu.ahs_len);
		}
		pdu.ahs_addr = isboot_malloc_pdubuf(pdu.ahs_size);
		if (pdu.ahs_addr == NULL) {
			ISBOOT_ERROR("isboot_malloc_pdubuf out of memory\n");
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			ISBOOT_TRACE("xpt_done %x\n", ccb->ccb_h.status);
			mtx_lock(&sess->cam_mtx);
			xpt_done(ccb);
			mtx_unlock(&sess->cam_mtx);
			return (ENOMEM);
		}
		/* fill in AHS by left bytes */
		ahs = (uint8_t *)&pdu.ahs_addr;
		memset(ahs, 0, pdu.ahs_size);
		/* first word is Length(includes reserved byte) and Type */
		DSET16(&ahs[0], (csio->cdb_len - 16) + 1);
		ahs[2] = 0x01;		/* Extended CDB */
		ahs[3] = 0x00;		/* Reserved */
		/* second... are ExtendedCDB and padding */
		if ((ccb_h->flags & CAM_CDB_POINTER) != 0) {
			memcpy(&ahs[4], ((uint8_t *)csio->cdb_io.cdb_ptr) + 16,
			    csio->cdb_len - 16);
		} else {
			memcpy(&ahs[4], ((uint8_t *)&csio->cdb_io.cdb_bytes) + 16,
			    csio->cdb_len - 16);
		}
	} else {
		if ((ccb_h->flags & CAM_CDB_POINTER) != 0) {
			memcpy(&req[32], csio->cdb_io.cdb_ptr,
			    csio->cdb_len);
		} else {
			memcpy(&req[32], csio->cdb_io.cdb_bytes,
			    csio->cdb_len);
		}
	}

	/* allocate new task */
	taskp = isboot_malloc(sizeof(*taskp));
	if (taskp == NULL) {
		ISBOOT_ERROR("taskq alloc error\n");
		ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		ISBOOT_TRACE("xpt_done %x\n", ccb->ccb_h.status);
		mtx_lock(&sess->cam_mtx);
		xpt_done(ccb);
		mtx_unlock(&sess->cam_mtx);
		return (ENOMEM);
	}
	memset(taskp, 0, sizeof(*taskp));
	taskp->ITT = 0xffffffffU;
	taskp->ccb = NULL;

	mtx_lock(&sess->task_mtx);
	ISBOOT_TRACE("add ccb\n");
	TAILQ_INSERT_TAIL(&sess->taskq, taskp, tasks);
	mtx_unlock(&sess->task_mtx);
	if (sess->cam_qfreeze != 0) {
		/* XXX should be removed in main thread */
		ISBOOT_TRACE("added ccb, qfreeze!=0\n");
		taskp->ccb = ccb;
		return (0);
	}

	TL = csio->dxfer_len;
	DSET32(&req[20], TL);
	mtx_lock_spin(&sess->sn_mtx);
	ITT = isboot_get_next_itt(sess);
	DSET32(&req[16], ITT);
	DSET32(&req[24], sess->cmdsn);
	DSET32(&req[28], sess->statsn);
	taskp->LUN = LUN;
	taskp->ITT = ITT;
	taskp->cmdsn = sess->cmdsn;
	taskp->ccb = ccb;
	sess->cmdsn++;
	mtx_unlock_spin(&sess->sn_mtx);

	if (csio->dxfer_len != 0) {
		if (csio->dxfer_len <= sess->opt.maxXmitDataSegmentLength)
			pdu.ds_size = csio->dxfer_len;
		else
			pdu.ds_size = sess->opt.maxXmitDataSegmentLength;
		pdu.ds_len = 0;
		pdu.ds_addr = isboot_malloc_pdubuf(pdu.ds_size);
		if (pdu.ds_addr == NULL) {
			ISBOOT_ERROR("isboot_malloc_pdubuf out of memory\n");
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			ISBOOT_TRACE("xpt_done %x\n", ccb->ccb_h.status);
			mtx_lock(&sess->cam_mtx);
			xpt_done(ccb);
			mtx_unlock(&sess->cam_mtx);
			return (ENOMEM);
		}
	} else {
		pdu.ds_size = 0;
		pdu.ds_len = 0;
		pdu.ds_addr = NULL;
	}

	/* immediate write */
	if (W_bit && sess->opt.immediateData) {
		immediatelen = min(sess->opt.firstBurstLength,
		    sess->opt.maxXmitDataSegmentLength);
		if (csio->dxfer_len <= immediatelen) {
			/* all in one data segment */
			memcpy(pdu.ds_addr, csio->data_ptr, csio->dxfer_len);
			pdu.ds_len = csio->dxfer_len;
			csio->resid = 0;
		} else {
			/* need R2T for more data */
			memcpy(pdu.ds_addr, csio->data_ptr, immediatelen);
			pdu.ds_len = immediatelen;
			csio->resid = csio->dxfer_len - immediatelen;
		}
	} else if (W_bit) {
		csio->resid = csio->dxfer_len;
	}

	error = isboot_xmit_pdu(sess, &pdu);
	if (error) {
		/* XXX should be removed in main thread */
		ISBOOT_ERROR("xmit pdu error=%d\n", error);
		if (sess->cam_qfreeze == 0) {
			xpt_freeze_simq(sess->sim, 1);
			xpt_freeze_devq(sess->path, 1);
			sess->cam_qfreeze++;
		}
		isboot_free_pdu(&pdu);
		return (error);
	}
	isboot_free_pdu(&pdu);
	return (0);
}

static void
isboot_xmit_thread(void *arg)
{
	struct isboot_sess *sess;
	struct action_xmit_task *taskp;

	sess = (struct isboot_sess *)arg;

	while (1) {
		mtx_lock(&sess->action_xmit_mtx);
		while (TAILQ_EMPTY(&sess->action_xmitq) &&
		    !sess->action_xmit_exit)
			cv_wait(&sess->action_xmit_cv, &sess->action_xmit_mtx);
		if (sess->action_xmit_exit) {
			while (!TAILQ_EMPTY(&sess->action_xmitq)) {
				taskp = TAILQ_FIRST(&sess->action_xmitq);
				TAILQ_REMOVE(&sess->action_xmitq, taskp, tasks);
				isboot_free(taskp);
			}
			sess->action_xmit_exit = false;
			sess->action_xmit_td = NULL;
			cv_signal(&sess->action_xmit_cv);
			mtx_unlock(&sess->action_xmit_mtx);
			break;
		}
		taskp = TAILQ_FIRST(&sess->action_xmitq);
		TAILQ_REMOVE(&sess->action_xmitq, taskp, tasks);
		mtx_unlock(&sess->action_xmit_mtx);

		isboot_scsi_io(sess, taskp->ccb);
		isboot_free(taskp);
	}

	kthread_exit();
}

static void
isboot_action(struct cam_sim *sim, union ccb *ccb)
{
	struct isboot_sess *sess;
	struct action_xmit_task *taskp;

	ISBOOT_TRACE("isboot action %x\n", ccb->ccb_h.func_code);
	sess = (struct isboot_sess *)cam_sim_softc(sim);

	switch (ccb->ccb_h.func_code) {
	case XPT_SCSI_IO:
	{
		if ((ccb->ccb_h.flags & CAM_CDB_POINTER) != 0) {
			if ((ccb->ccb_h.flags & CAM_CDB_PHYS) != 0) {
				ccb->ccb_h.status = CAM_REQ_INVALID;
				break;
			}
		}
		taskp = isboot_malloc(sizeof(*taskp));
		taskp->ccb = ccb;
		mtx_lock(&sess->action_xmit_mtx);
		TAILQ_INSERT_TAIL(&sess->action_xmitq, taskp, tasks);
		cv_signal(&sess->action_xmit_cv);
		mtx_unlock(&sess->action_xmit_mtx);
		return;
	}
	case XPT_CALC_GEOMETRY:
	{
		struct ccb_calc_geometry *ccg = &ccb->ccg;

		ISBOOT_TRACE("XPT_CALC_GEOMETRY\n");
		ISBOOT_TRACE("target=%d, lun=%d vsize=%d, bsize=%d\n",
		    ccb->ccb_h.target_id, (int)ccb->ccb_h.target_lun,
		    (int)ccg->volume_size, (int)ccg->block_size);
		cam_calc_geometry(ccg, /*extended*/1);
		break;
	}
	case XPT_PATH_INQ:
	{
		struct ccb_pathinq *cpi = &ccb->cpi;
		
		cpi->version_num = 1;
		cpi->hba_inquiry = PI_TAG_ABLE;
		cpi->target_sprt = 0;
		cpi->hba_misc = PIM_NOBUSRESET;
		cpi->hba_eng_cnt = 0;
		cpi->max_target = 0;
		cpi->max_lun = ISBOOT_MAX_LUNS;
		cpi->initiator_id = cpi->max_lun + 1;
		strncpy(cpi->sim_vid, "FreeBSD", SIM_IDLEN);
		strncpy(cpi->hba_vid, "iSCSI", HBA_IDLEN);
		strncpy(cpi->dev_name, cam_sim_name(sim), DEV_IDLEN);
		cpi->unit_number = cam_sim_unit(sim);
		cpi->bus_id = cam_sim_bus(sim);
		cpi->base_transfer_speed = 300000;
		cpi->protocol = PROTO_SCSI;
#ifdef SCSI_REV_SPC3
		cpi->protocol_version = SCSI_REV_SPC3;
#else
		cpi->protocol_version = SCSI_REV_SPC2;
#endif
		cpi->transport = XPORT_ISCSI;
		cpi->transport_version = 0;
		cpi->maxio = 1024 * 1024;
		cpi->ccb_h.status = CAM_REQ_CMP;
		break;
	}
	case XPT_GET_TRAN_SETTINGS:
	{
		ccb->cts.protocol = PROTO_SCSI;
#ifdef SCSI_REV_SPC3
		ccb->cts.protocol_version = SCSI_REV_SPC3;
#else
		ccb->cts.protocol_version = SCSI_REV_SPC2;
#endif
		ccb->cts.transport = XPORT_ISCSI;
		ccb->cts.transport_version = 0;
		ccb->ccb_h.status = CAM_REQ_CMP;
		break;
	}
	case XPT_SET_TRAN_SETTINGS:
		ccb->ccb_h.status = CAM_FUNC_NOTAVAIL;
		break;
	case XPT_RESET_BUS:
		ccb->ccb_h.status = CAM_REQ_CMP;
		break;
	case XPT_RESET_DEV:
		ccb->ccb_h.status = CAM_REQ_CMP;
		break;
	default:
		ccb->ccb_h.status = CAM_REQ_INVALID;
		break;
	}
	xpt_done(ccb);
	ISBOOT_TRACE("isboot action %x done\n", ccb->ccb_h.func_code);
}

static void
isboot_poll(struct cam_sim *sim)
{
	struct isboot_sess *sess;
	static int poll_out = 0;

	if (poll_out == 0) {
		poll_out = 1;
		ISBOOT_TRACE("isboot poll\n");
	}
	sess = (struct isboot_sess *)cam_sim_softc(sim);
	/* called after crash dump */
	/* XXX need flush? */
}

static int
isboot_cam_attach(struct isboot_sess *sess)
{
	struct cam_devq *devq;
	struct cam_sim *sim;
	int maxq = 255;

	ISBOOT_TRACE("cam attach\n");

	/* device queue */
	devq = cam_simq_alloc(maxq);
	if (devq == NULL) {
		ISBOOT_ERROR("simq alloc error\n");
		return (ENOMEM);
	}

	/* construct sim */
	mtx_init(&sess->cam_mtx, "isboot", NULL, MTX_DEF);
	sim = cam_sim_alloc(isboot_action, isboot_poll, "isboot",
	    sess, sess->unit, &sess->cam_mtx, /*max_dev_transactions*/1,
	    maxq, devq);
	if (sim == NULL) {
		ISBOOT_ERROR("sim alloc error\n");
		cam_simq_free(devq);
		mtx_destroy(&sess->cam_mtx);
		return (ENOMEM);
	}

	/* register bus */
	mtx_lock(&sess->cam_mtx);
	if (xpt_bus_register(sim, NULL, /*bus*/0) != CAM_SUCCESS) {
		ISBOOT_ERROR("bus registration failed\n");
		mtx_unlock(&sess->cam_mtx);
		cam_sim_free(sim, /*free_devq*/TRUE);
		mtx_destroy(&sess->cam_mtx);
		return (ENOMEM);
	}
	if (xpt_create_path(&sess->path, xpt_periph, cam_sim_path(sim),
		CAM_TARGET_WILDCARD, CAM_LUN_WILDCARD) != CAM_REQ_CMP) {
		ISBOOT_ERROR("path alloc error\n");
		mtx_unlock(&sess->cam_mtx);
		xpt_bus_deregister(cam_sim_path(sim));
		cam_sim_free(sim, /*free_devq*/TRUE);
		mtx_destroy(&sess->cam_mtx);
		return (ENOMEM);
	}
	sess->sim = sim;
	mtx_unlock(&sess->cam_mtx);

	ISBOOT_TRACE("cam attach end\n");
	return (0);
}

static int
isboot_cam_dettach(struct isboot_sess *sess)
{

	ISBOOT_TRACE("cam dettach\n");

	mtx_lock(&sess->cam_mtx);
	if (sess->sim != NULL) {
		xpt_async(XPT_RESET_BUS, sess->path, NULL);
		xpt_free_path(sess->path);
		xpt_bus_deregister(cam_sim_path(sess->sim));
		cam_sim_free(sess->sim, /*free_devq*/TRUE);
		sess->sim = NULL;
		sess->path = NULL;
	}
	mtx_unlock(&sess->cam_mtx);

	ISBOOT_TRACE("cam dettach end\n");
	return (0);
}

static void
isboot_cam_rescan_done(struct cam_periph *periph, union ccb *ccb)
{
	struct isboot_sess *sess;

	ISBOOT_TRACE("cam rescan done\n");
	sess = (struct isboot_sess *)ccb->ccb_h.spriv_ptr0;
	sess->cam_rescan_done = 1;
	sess->cam_rescan_in_progress = 0;
	wakeup(&sess->cam_rescan_done);
	xpt_free_ccb(ccb);
}

static int
isboot_cam_rescan(struct isboot_sess *sess)
{
	union ccb  *ccb;

	/* this action will issue SCSI commands to iSCSI layer
	 * you must prepare receiver before calling it
	 * and should not block here (main thread)
	 */
	ISBOOT_TRACE("cam rescan\n");
	ccb = xpt_alloc_ccb();
	mtx_lock(&sess->cam_mtx);
	if (sess->sim != NULL && sess->path != NULL) {
		//xpt_path_lock(ccb->ccb_h.path);
		xpt_path_lock(sess->path);
		xpt_setup_ccb(&ccb->ccb_h, sess->path, /*priority*/5);
		ccb->ccb_h.func_code = XPT_SCAN_BUS;
		ccb->ccb_h.target_id = CAM_TARGET_WILDCARD;
		ccb->ccb_h.target_lun = CAM_LUN_WILDCARD;
		ccb->ccb_h.cbfcnp = isboot_cam_rescan_done;
		ccb->crcn.flags = CAM_FLAG_NONE;
		ccb->ccb_h.spriv_ptr0 = sess;
		sess->cam_rescan_done = 0;
		sess->cam_rescan_in_progress = 1;
		xpt_action(ccb);
		//xpt_path_unlock(ccb->ccb_h.path);
		xpt_path_unlock(sess->path);
		ccb = NULL;	/* free by callback */
	}
	mtx_unlock(&sess->cam_mtx);
	if (ccb != NULL)
		xpt_free_ccb(ccb);
	ISBOOT_TRACE("cam rescan end\n");
	return (0);
}

static void
isboot_destroy_sess(struct isboot_sess *sess)
{

	ISBOOT_TRACE("isboot destroy session\n");
	if (sess == NULL)
		return;
	if (sess->action_xmit_td != NULL) {
		mtx_lock(&sess->action_xmit_mtx);
		sess->action_xmit_exit = true;
		do {
			cv_signal(&sess->action_xmit_cv);
			cv_wait(&sess->action_xmit_cv, &sess->action_xmit_mtx);
		} while (sess->action_xmit_exit);
		mtx_unlock(&sess->action_xmit_mtx);
	}
	if (sess->so != NULL) {
		soclose(sess->so);
		sess->so = NULL;
	}
	isboot_free_str(sess->opt.initiatorName);
	sess->opt.initiatorName = NULL;
	isboot_free_str(sess->opt.targetName);
	sess->opt.targetName = NULL;
	isboot_free_str(sess->opt.targetAddress);
	sess->opt.targetAddress = NULL;
	isboot_free_str(sess->opt.authMethod);
	sess->opt.authMethod = NULL;
	isboot_free_str(sess->opt.headerDigest);
	sess->opt.headerDigest = NULL;
	isboot_free_str(sess->opt.dataDigest);
	sess->opt.dataDigest = NULL;

	isboot_free_str(sess->auth.algorithm);
	sess->auth.algorithm = NULL;
	isboot_free_str(sess->auth.user);
	sess->auth.user = NULL;
	isboot_free_str(sess->auth.secret);
	sess->auth.secret = NULL;
	isboot_free_str(sess->auth.muser);
	sess->auth.muser = NULL;
	isboot_free_str(sess->auth.msecret);
	sess->auth.msecret = NULL;

	mtx_destroy(&sess->xmit_mtx);
	mtx_destroy(&sess->sn_mtx);
	mtx_destroy(&sess->task_mtx);

	cv_destroy(&sess->action_xmit_cv);
	mtx_destroy(&sess->action_xmit_mtx);
}

static int
isboot_stop(struct isboot_sess *sess)
{

	/* full feature down */
	if (sess->so != NULL) {
		soclose(sess->so);
		sess->so = NULL;
	}
	sess->full_feature = 0;
	sess->tsih = 0;

	/* reset digest mode for login */
	isboot_free_str(sess->opt.headerDigest);
	sess->opt.headerDigest = isboot_strdup(isboot_opt_hd);
	isboot_free_str(sess->opt.dataDigest);
	sess->opt.dataDigest = isboot_strdup(isboot_opt_dd);
	sess->header_digest = 0;
	sess->data_digest = 0;

	/* reset auth mode */
	isboot_free_str(sess->opt.authMethod);
	if (sess->req_auth != 0 || sess->req_mutual != 0) {
		sess->opt.authMethod = isboot_strdup("CHAP,None");
	} else {
		sess->opt.authMethod = isboot_strdup("None");
	}
	isboot_free_str(sess->auth.algorithm);
	sess->auth.algorithm = NULL;

	return (0);
}

static int
isboot_close(struct isboot_sess *sess)
{

	return (0);
}

static int
isboot_initialize_session(struct isboot_sess *sess)
{
	int error = 0;

	ISBOOT_TRACE("initialize session, thread id=%x\n", curthread->td_tid);
	sess->td = curthread;
	strlcpy(sess->initiator_name, (char *)isboot_initiator_name,
	    ISBOOT_NAME_MAX);
	strlcpy(sess->target_name, (char *)isboot_target_name,
	    ISBOOT_NAME_MAX);
	memcpy(&sess->initiator_address, isboot_initiator_address,
	    IBFT_IP_LEN);
	memcpy(&sess->target_address, isboot_target_address, IBFT_IP_LEN);
	sess->port = isboot_target_port;
	sess->lun = isboot_target_lun;

	ISBOOT_TRACE("Initiator: %s\n", isboot_initiator_name);
	ISBOOT_TRACE("Target: %s\n", isboot_target_name);
	ISBOOT_TRACE("Target IP=%s, Port=%u, LUN=%ju\n",
	    isboot_target_address_string, isboot_target_port,
	    (intmax_t)isboot_target_lun);

	/* session for path(index)=1, connection=1 */
	sess->isid = isboot_get_isid(1);
	sess->tsih = 0;
	sess->cid = 1;

	/* initialize parameters */
	sess->so = NULL;
	// NOT USE
	//sess->sp = NULL;
	sess->fd = -1;
	sess->timeout = ISBOOT_SOCK_TIMEOUT;
	sess->header_digest = 0;
	sess->data_digest = 0;
	sess->full_feature = 0;
	sess->reconnect = 0;
	sess->stage = ISBOOT_NO_STAGE;
	sess->chap_stage = ISBOOT_CHAP_NONE;
	sess->discovery = 0;
	sess->authenticated = 0;
	sess->auth.algorithm = NULL;
	if (isboot_chap_type == 1) {
		/* CHAP */
		sess->req_auth = 1;
		sess->req_mutual = 0;
		sess->auth.user = isboot_strdup(isboot_chap_name);
		sess->auth.secret = isboot_strdup(isboot_chap_secret);
		sess->auth.muser = NULL;
		sess->auth.msecret = NULL;
	} else if (isboot_chap_type == 2) {
		/* Mutual CHAP */
		sess->req_auth = 1;
		sess->req_mutual = 1;
		sess->auth.user = isboot_strdup(isboot_chap_name);
		sess->auth.secret = isboot_strdup(isboot_chap_secret);
		sess->auth.muser = isboot_strdup(isboot_rev_chap_name);
		sess->auth.msecret = isboot_strdup(isboot_rev_chap_secret);
	} else {
		/* No CHAP */
		sess->req_auth = 0;
		sess->req_mutual = 0;
		sess->auth.user = NULL;
		sess->auth.secret = NULL;
		sess->auth.muser = NULL;
		sess->auth.msecret = NULL;
	}
	sess->auth.chap_id[0] = 0;
	sess->auth.chap_mid[0] = 0;
	sess->auth.chap_challenge_len = -1;
	sess->auth.chap_mchallenge_len = -1;
	sess->auth.chap_mresponse_len = -1;

	/* iSCSI options */
	sess->opt.initiatorName = isboot_strdup(sess->initiator_name);
	sess->opt.targetName = isboot_strdup(sess->target_name);
	sess->opt.targetAddress = isboot_strdup(isboot_target_address_string);
	sess->opt.port = sess->port;
	sess->opt.targetPortalGroupTag = 1;
	sess->opt.tags = ISBOOT_CAM_TAGS;
	if (sess->req_auth != 0 || sess->req_mutual != 0) {
		sess->opt.authMethod = isboot_strdup("CHAP,None");
	} else {
		sess->opt.authMethod = isboot_strdup("None");
	}
	sess->opt.headerDigest = isboot_strdup(isboot_opt_hd);
	sess->opt.dataDigest = isboot_strdup(isboot_opt_dd);
	sess->opt.defaultTime2Wait = 2;
	sess->opt.defaultTime2Retain = 60;
	sess->opt.errorRecoveryLevel = 0;
	sess->opt.maxConnections = 1;
	sess->opt.initialR2T = TRUE;
	sess->opt.immediateData = TRUE;
	sess->opt.maxOutstandingR2T = 1;
	sess->opt.dataPDUInOrder = TRUE;
	sess->opt.dataSequenceInOrder = TRUE;
	/* default MaxRecvDataSegmentLength 12.12 */
	sess->opt.maxXmitDataSegmentLength = 8192;
	/* istgt 20100525 default values */
	sess->opt.maxRecvDataSegmentLength = 262144;
	sess->opt.firstBurstLength = 262144;
	sess->opt.maxBurstLength = 1048576;

	/* for initial command */
	sess->cmdsn = 0;
	sess->statsn = 0;
	sess->itt = 0;

	/* mutex */
	mtx_init(&sess->xmit_mtx, "isboot", NULL, MTX_DEF);
	mtx_init(&sess->sn_mtx, "isboot", NULL, MTX_SPIN);
	mtx_init(&sess->task_mtx, "isboot", NULL, MTX_DEF);

	/* queue */
	TAILQ_INIT(&sess->taskq);

	/* Action transmission worker initialization */
	TAILQ_INIT(&sess->action_xmitq);
	sess->action_xmit_exit = false;
	mtx_init(&sess->action_xmit_mtx, "isboot action xmit mtx", NULL, MTX_DEF);
	cv_init(&sess->action_xmit_cv, NULL);
	sess->action_xmit_td = NULL;
	kthread_add(isboot_xmit_thread, sess, sess->pp, &sess->action_xmit_td,
	    0, 0, "isboot tx");

	/* cam stuff */
	sess->unit = 0;
	sess->sim = NULL;
	sess->path = NULL;
	sess->cam_rescan_done = 0;
	sess->cam_rescan_in_progress = 0;
	sess->cam_device_installed = 0;
	sess->cam_qfreeze = 0;

	return (error);
}

static int
isboot_start_session(struct isboot_sess *sess)
{
	int error;

	/* start iSCSI session */
	ISBOOT_TRACE("isboot_connect\n");
	error = isboot_connect(sess);
	if (error) {
		ISBOOT_ERROR("connect failed\n");
		return (error);
	}

	ISBOOT_TRACE("isboot_do_login\n");
	error = isboot_do_login(sess);
	if (error) {
		ISBOOT_ERROR("do login failed\n");
		return (error);
	}

	/* now full feature phase */
	return (0);
}

static struct isboot_task *
isboot_get_task(struct isboot_sess *sess, uint32_t ITT)
{
	struct isboot_task *taskp;

	if (ITT == 0xffffffffU)
		return (NULL);
	TAILQ_FOREACH(taskp, &sess->taskq, tasks) {
		if (taskp->ITT == ITT) {
			return (taskp);
		}
	}
	return (NULL);
}

static int
isboot_rsp_scsi(struct isboot_sess *sess, pdu_t *pp)
{
	uint8_t *rsp = (uint8_t *)&pp->ipdu.bhs;
	uint8_t *sp;
	struct isboot_task *taskp;
	union ccb *ccb;
	uint32_t ITT, SNT;
	uint32_t StatSN;
	uint32_t ExpCmdSN, MaxCmdSN;
	uint32_t ExpDataSN;
	int status, response;
	int o_bit, u_bit, O_bit, U_bit;
	int residual;
	int bidi_residual;
	int len, sense_len;

	ITT = DGET32(&rsp[16]);
	mtx_lock(&sess->task_mtx);
	taskp = isboot_get_task(sess, ITT);
	if (taskp != NULL)
		ccb = taskp->ccb;
	else
		ccb = NULL;
	mtx_unlock(&sess->task_mtx);

	if (ccb == NULL) {
		ISBOOT_ERROR("ccb == NULL\n");
		return (EINVAL);
	}

	o_bit = BGET8(&rsp[1], 4);
	u_bit = BGET8(&rsp[1], 3);
	O_bit = BGET8(&rsp[1], 2);
	U_bit = BGET8(&rsp[1], 1);

	response = DGET8(&rsp[2]);
	status = DGET8(&rsp[3]);
	StatSN = DGET32(&rsp[24]);
	mtx_lock_spin(&sess->sn_mtx);
	sess->statsn++;
	mtx_unlock_spin(&sess->sn_mtx);

	ITT = DGET32(&rsp[16]);
	SNT = DGET32(&rsp[20]);
	ExpCmdSN = DGET32(&rsp[28]);
	MaxCmdSN = DGET32(&rsp[32]);
	ExpDataSN = DGET32(&rsp[36]);
	bidi_residual = DGET32(&rsp[40]);
	residual = DGET32(&rsp[44]);

	if (pp->ds_len > 2) {
		sense_len = DGET16(&pp->ds_addr[0]);
		sp = (uint8_t *)&pp->ds_addr[2];
	} else {
		sense_len = 0;
		sp = NULL;
	}

	ISBOOT_TRACE("CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, "
	    "MaxCmdSN=%u\n", sess->cmdsn, sess->statsn,
	    StatSN, ExpCmdSN, MaxCmdSN);
	ISBOOT_TRACE("ExpDataSN=%u\n", ExpDataSN);
	ISBOOT_TRACE("o=%d, u=%d, O=%d, U=%d\n", o_bit, u_bit, O_bit, U_bit);

	ccb->csio.resid = 0;
	if (O_bit)
		ccb->csio.resid = -residual;
	if (U_bit)
		ccb->csio.resid = residual;

	ccb->ccb_h.status = CAM_REQ_CMP_ERR;
	if (response == 0x00) {
		ccb->csio.scsi_status = status;
		memset(&ccb->csio.sense_data, 0, sizeof(ccb->csio.sense_data));
		if (sense_len != 0) {
			len = min(sense_len, ccb->csio.sense_len);
			memcpy(&ccb->csio.sense_data, sp, len);
			ccb->csio.sense_resid = ccb->csio.sense_len - len;
		}
		switch (status) {
		case 0x00: /* GOOD */
			ccb->ccb_h.status = CAM_REQ_CMP;
			break;
		case 0x02: /* CHECK CONDITION */
			ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
			break;
		case 0x04: /* CONDITION MET */
			ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
			break;
		case 0x08: /* BUSY */
			ccb->ccb_h.status = CAM_SCSI_BUSY;
			break;
		case 0x10: /* INTERMEDIATE */
			ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
			break;
		case 0x14: /* INTERMEDIATE-CONDITION MET */
			ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
			break;
		case 0x18: /* RESERVATION CONFLICT */
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			break;
		case 0x22: /* Obsolete */
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			break;
		case 0x28: /* TASK SET FULL */
			ccb->ccb_h.status = CAM_REQUEUE_REQ;
			break;
		case 0x30: /* ACA ACTIVE */
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			break;
		case 0x40: /* TASK ABORTED */
			ccb->ccb_h.status = CAM_REQ_ABORTED;
			break;
		default:
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
			break;
		}
		if (sense_len != 0) {
			ISBOOT_TRACE("auto sense valid\n");
			ccb->ccb_h.status |= CAM_AUTOSNS_VALID;
		}
	} else {
		ccb->ccb_h.status = CAM_REQ_CMP_ERR;
	}

	ISBOOT_TRACE("xpt_done %x\n", ccb->ccb_h.status);
	mtx_lock(&sess->cam_mtx);
	xpt_done(ccb);
	mtx_unlock(&sess->cam_mtx);

	mtx_lock(&sess->task_mtx);
	ISBOOT_TRACE("remove ccb ITT=%x\n", taskp->ITT);
	TAILQ_REMOVE(&sess->taskq, taskp, tasks);
	wakeup(&sess->taskq);
	mtx_unlock(&sess->task_mtx);
	isboot_free(taskp);

	return (0);
}

static int
isboot_rsp_read_data(struct isboot_sess *sess, pdu_t *pp)
{
	uint8_t *rsp = (uint8_t *)&pp->ipdu.bhs;
	struct isboot_task *taskp;
	union ccb *ccb;
	uint8_t *data;
	uint32_t ITT, TTT;
	uint32_t StatSN;
	uint32_t ExpCmdSN, MaxCmdSN;
	uint32_t DataSN, ExpDataSN;
	uint32_t TL;
	int error;
	int offset;
	int status, response;
	int len;
	int F_bit, O_bit, U_bit, S_bit;
	int residual;

	ITT = DGET32(&rsp[16]);
	mtx_lock(&sess->task_mtx);
	taskp = isboot_get_task(sess, ITT);
	if (taskp != NULL)
		ccb = taskp->ccb;
	else
		ccb = NULL;
	mtx_unlock(&sess->task_mtx);

	if (ccb == NULL) {
		ISBOOT_ERROR("ccb == NULL\n");
		return (EINVAL);
	}

	data = ccb->csio.data_ptr;
	offset = 0;
	ExpDataSN = 0;

	TL = ccb->csio.dxfer_len;
	len = pp->ds_len;
	status = 0;
	response = 0;
	error = 0;

	F_bit = BGET8(&rsp[1], 7);
	S_bit = BGET8(&rsp[1], 0);
	if (F_bit && S_bit) {
		O_bit = BGET8(&rsp[1], 2);
		U_bit = BGET8(&rsp[1], 1);
	} else {
		O_bit = U_bit = 0;
	}
	if (S_bit) {
		status = DGET8(&rsp[3]);
		StatSN = DGET32(&rsp[24]);
		mtx_lock_spin(&sess->sn_mtx);
		sess->statsn++;
		mtx_unlock_spin(&sess->sn_mtx);
	} else {
		status = 0;
		StatSN = 0;
	}
	ITT = DGET32(&rsp[16]);
	TTT = DGET32(&rsp[20]);
	ExpCmdSN = DGET32(&rsp[28]);
	MaxCmdSN = DGET32(&rsp[32]);
	DataSN = DGET32(&rsp[36]);
	offset = DGET32(&rsp[40]);
	residual = DGET32(&rsp[44]);

	if (offset > TL || (offset + len) > TL) {
		ISBOOT_ERROR("transfer request error\n");
		return (EINVAL);
	}

	ISBOOT_TRACE("CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, "
	    "MaxCmdSN=%u\n", sess->cmdsn, sess->statsn,
	    StatSN, ExpCmdSN, MaxCmdSN);

	ISBOOT_TRACE("F=%d, S=%d, O=%d, U=%d\n", F_bit, S_bit, O_bit, U_bit);
	ISBOOT_TRACE("TL=%d, offset=%d, len=%d\n", TL, offset, len);
	memcpy(data + offset, pp->ds_addr, ISCSI_ALIGN(pp->ds_len));
	ExpDataSN++;

	if (S_bit) {
		ccb->csio.resid = 0;
		if (O_bit)
			ccb->csio.resid = -residual;
		if (U_bit)
			ccb->csio.resid = residual;

		ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		if (response == 0x00) {
			switch (status) {
			case 0x00: /* GOOD */
				ccb->ccb_h.status = CAM_REQ_CMP;
				break;
			case 0x02: /* CHECK CONDITION */
				ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
				break;
			case 0x04: /* CONDITION MET */
				ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
				break;
			case 0x08: /* BUSY */
				ccb->ccb_h.status = CAM_SCSI_BUSY;
				break;
			case 0x10: /* INTERMEDIATE */
				ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
				break;
			case 0x14: /* INTERMEDIATE-CONDITION MET */
				ccb->ccb_h.status = CAM_SCSI_STATUS_ERROR;
				break;
			case 0x18: /* RESERVATION CONFLICT */
				ccb->ccb_h.status = CAM_REQ_CMP_ERR;
				break;
			case 0x22: /* Obsolete */
				ccb->ccb_h.status = CAM_REQ_CMP_ERR;
				break;
			case 0x28: /* TASK SET FULL */
				ccb->ccb_h.status = CAM_REQUEUE_REQ;
				break;
			case 0x30: /* ACA ACTIVE */
				ccb->ccb_h.status = CAM_REQ_CMP_ERR;
				break;
			case 0x40: /* TASK ABORTED */
				ccb->ccb_h.status = CAM_REQ_ABORTED;
				break;
			default:
				ccb->ccb_h.status = CAM_REQ_CMP_ERR;
				break;
			}
		} else {
			ccb->ccb_h.status = CAM_REQ_CMP_ERR;
		}
		ISBOOT_TRACE("xpt_done %x\n", ccb->ccb_h.status);
		mtx_lock(&sess->cam_mtx);
		xpt_done(ccb);
		mtx_unlock(&sess->cam_mtx);
	}
	if (F_bit) {
		mtx_lock(&sess->task_mtx);
		ISBOOT_TRACE("remove ccb ITT=%x\n", taskp->ITT);
		TAILQ_REMOVE(&sess->taskq, taskp, tasks);
		wakeup(&sess->taskq);
		mtx_unlock(&sess->task_mtx);
		isboot_free(taskp);
	}
	return (0);
}

static int
isboot_rsp_r2t(struct isboot_sess *sess, pdu_t *pp)
{
	pdu_t data_pdu;
	uint8_t *rsp = (uint8_t *)&pp->ipdu.bhs;
	uint8_t *cp;
	struct isboot_task *taskp;
	union ccb *ccb;
	uint8_t *data;
	uint64_t LUN;
	uint32_t ITT, TTT;
	uint32_t R2TSN;
	uint32_t StatSN;
	uint32_t ExpCmdSN, MaxCmdSN;
	uint32_t DataSN;
	uint32_t TL;
	int error;
	int offset;
	int len;
	int F_bit;
	int maxburst_len;
	int transfer_len;
	int segment_len;
	int ds_len;

	ITT = DGET32(&rsp[16]);
	mtx_lock(&sess->task_mtx);
	taskp = isboot_get_task(sess, ITT);
	if (taskp != NULL)
		ccb = taskp->ccb;
	else
		ccb = NULL;
	mtx_unlock(&sess->task_mtx);

	if (ccb == NULL) {
		ISBOOT_ERROR("ccb == NULL\n");
		return (EINVAL);
	}

	memset(&data_pdu, 0, sizeof(data_pdu));
	data = ccb->csio.data_ptr;
	TL = ccb->csio.dxfer_len;
	error = 0;

	LUN = DGET64(&rsp[8]);
	ITT = DGET32(&rsp[16]);
	TTT = DGET32(&rsp[20]);
	ExpCmdSN = DGET32(&rsp[28]);
	MaxCmdSN = DGET32(&rsp[32]);
	R2TSN = DGET32(&rsp[36]);
	offset = DGET32(&rsp[40]);
	len = DGET32(&rsp[44]);

	if (offset > TL || (offset + len) > TL) {
		ISBOOT_ERROR("transfer request error\n");
		return (EINVAL);
	}
	maxburst_len = min(TL - offset, sess->opt.maxBurstLength);
	transfer_len = min(len, maxburst_len);
	segment_len = sess->opt.maxXmitDataSegmentLength;
	len = 0;
	F_bit = 0;
	DataSN = 0;
	mtx_lock_spin(&sess->sn_mtx);
	StatSN = sess->statsn;
	mtx_unlock_spin(&sess->sn_mtx);

	data_pdu.ahs_size = 0;
	data_pdu.ahs_len = 0;
	data_pdu.ahs_addr = NULL;
	data_pdu.ds_size = segment_len;
	data_pdu.ds_len = 0;
	data_pdu.ds_addr = isboot_malloc_pdubuf(data_pdu.ds_size);
	if (data_pdu.ds_addr == NULL)
		return (ENOMEM);

	ISBOOT_TRACE("CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, "
	    "MaxCmdSN=%u\n", sess->cmdsn, sess->statsn,
	    StatSN, ExpCmdSN, MaxCmdSN);

	ISBOOT_TRACE("TL=%d, offset=%d, len=%d\n", TL, offset, transfer_len);
	while ((transfer_len - len) > 0) {
		ds_len = min(transfer_len - len, segment_len);
		memcpy(data_pdu.ds_addr, data + offset, ds_len);
		data_pdu.ds_len = ds_len;
		len += ds_len;
		if ((transfer_len - len) == 0) {
			F_bit = 1;
		}

		/* SCSI Data-Out */
		cp = (uint8_t *)&data_pdu.ipdu.bhs;
		cp[0] = ISCSI_OP_WRITE_DATA;
		BDADD8(&cp[1], F_bit, 7);
		cp[4] = 0;		/* TotalAHSLength */
		DSET24(&cp[5], ds_len);	/* DataSegmentLength */
		DSET64(&cp[8], LUN);
		DSET32(&cp[16], ITT);
		DSET32(&cp[20], TTT);
		DSET32(&cp[28], StatSN);
		DSET32(&cp[36], DataSN);
		DataSN++;
		DSET32(&cp[40], offset);
		offset += ds_len;
		error = isboot_xmit_pdu(sess, &data_pdu);
		if (error) {
			ISBOOT_TRACE("R2T transfer error\n");
			isboot_free_pdu(&data_pdu);
			return (error);
		}
	}
	isboot_free_pdu(&data_pdu);
	return (0);
}

static int
isboot_send_nopout(struct isboot_sess *sess, pdu_t *pp, uint32_t *TTT_in)
{
	uint8_t *req = (uint8_t *)&pp->ipdu.bhs;
	uint64_t LUN;
	uint32_t ITT, TTT;
	int I_bit;
	int error;

	memset(pp, 0, sizeof(*pp));
	req = (uint8_t *)&pp->ipdu.bhs;
	req[0] = ISCSI_OP_NOP_OUT;
	if (TTT_in == NULL) {
		I_bit = 0;
		TTT = 0xffffffffU;
	}
	else {
		I_bit = 1;
		TTT = *TTT_in;
		ITT = 0xffffffffU;
	}
	BDADD8(&req[0], I_bit, 6);
	req[4] = 0;		/* TotalAHSLength */
	DSET24(&req[5], 0);	/* DataSegmentLength */
	LUN = isboot_lun2islun(sess->lun, ISBOOT_MAX_LUNS);
	DSET64(&req[8], LUN);
	mtx_lock_spin(&sess->sn_mtx);
	if (TTT_in == NULL) {
		ITT = isboot_get_next_itt(sess);
	}
	DSET32(&req[16], ITT);
	DSET32(&req[20], TTT);
	DSET32(&req[24], sess->cmdsn);
	DSET32(&req[28], sess->statsn);
	if (I_bit == 0) {
		sess->cmdsn++;
	}
	mtx_unlock_spin(&sess->sn_mtx);

	ISBOOT_TRACE("NOP OUT ITT=0x%x, TTT=0x%x\n", ITT, TTT);
	error = isboot_xmit_pdu(sess, pp);
	if (error) {
		isboot_free_pdu(pp);
		return (error);
	}
	isboot_free_pdu(pp);
	return (0);
}

static int
isboot_rsp_nopin(struct isboot_sess *sess, pdu_t *pp)
{
	uint8_t *rsp = (uint8_t *)&pp->ipdu.bhs;
	uint64_t LUN;
	uint32_t ITT, TTT;
	uint32_t StatSN;
	uint32_t ExpCmdSN, MaxCmdSN;
	int error = 0;

	LUN = DGET64(&rsp[8]);
	ITT = DGET32(&rsp[16]);
	TTT = DGET32(&rsp[20]);
	StatSN = DGET32(&rsp[24]);
	ExpCmdSN = DGET32(&rsp[28]);
	MaxCmdSN = DGET32(&rsp[32]);

	ISBOOT_TRACE("CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, "
	    "MaxCmdSN=%u\n", sess->cmdsn, sess->statsn,
	    StatSN, ExpCmdSN, MaxCmdSN);

	/* target initiated */
	if (TTT == 0xffffffffU) {
		/* response is unnecessary */
		ISBOOT_TRACE("TTT=0xffffffff\n");
		/* 10.19.2 */
		if (ITT != 0xffffffffU) {
			mtx_lock_spin(&sess->sn_mtx);
			sess->statsn++;
			mtx_unlock_spin(&sess->sn_mtx);
		}
		return (0);
	}

	/* response of previous NOPOUT */
	/* 10.19.2 */
	if (ITT != 0xffffffffU) {
		mtx_lock_spin(&sess->sn_mtx);
		sess->statsn++;
		mtx_unlock_spin(&sess->sn_mtx);
	}
	/* send "ping" response */
	else {
		error = isboot_send_nopout(sess, pp, &TTT);
		if (error) {
			ISBOOT_ERROR("send nopout error\n");
		}
	}
	return (0);
}

static int
isboot_execute(struct isboot_sess *sess, pdu_t *pp)
{
	uint8_t *bhs = (uint8_t *)&pp->ipdu.bhs;
	int immediate, opcode;
	int rc;

	if (pp == NULL)
		return (EINVAL);

	immediate = BGET8W(&bhs[0], 6, 1);
	opcode = BGET8W(&bhs[0], 5, 6);

	ISBOOT_TRACE("isboot_execute opcode=0x%x\n", opcode);
	switch (opcode) {
	case ISCSI_OP_NOP_IN:
		ISBOOT_TRACE("NOP IN\n");
		rc = isboot_rsp_nopin(sess, pp);
		if (rc != 0) {
			return (rc);
		}
		break;
	case ISCSI_OP_SCSI_RSP:
		ISBOOT_TRACE("SCSI RSP\n");
		rc = isboot_rsp_scsi(sess, pp);
		if (rc != 0) {
			return (rc);
		}
		break;
	case ISCSI_OP_TASK_RSP:
		ISBOOT_TRACE("TASK RSP\n");
		goto error_out;
		break;
	case ISCSI_OP_LOGIN_RSP:
		ISBOOT_TRACE("LOGIN RSP\n");
		goto error_out;
		break;
	case ISCSI_OP_TEXT_RSP:
		ISBOOT_TRACE("TEXT RSP\n");
		goto error_out;
		break;
	case ISCSI_OP_READ_DATA:
		ISBOOT_TRACE("READ DATA\n");
		rc = isboot_rsp_read_data(sess, pp);
		if (rc != 0) {
			return (rc);
		}
		break;
	case ISCSI_OP_LOGOUT_RSP:
		ISBOOT_TRACE("LOGOUT RSP\n");
		goto error_out;
		break;
	case ISCSI_OP_R2T:
		ISBOOT_TRACE("R2T\n");
		rc = isboot_rsp_r2t(sess, pp);
		if (rc != 0) {
			return (rc);
		}
		break;
	case ISCSI_OP_ASYNC_MSG:
		ISBOOT_TRACE("ASYNC\n");
		goto error_out;
	case ISCSI_OP_REJECT:
		ISBOOT_TRACE("REJECT\n");
		goto error_out;
	default:
	error_out:
		ISBOOT_TRACE("unsupported opcode %x\n", pp->ipdu.bhs.opcode);
		return (EOPNOTSUPP);
	}
	return (0);
}

static int
isboot_peek_bhs(struct isboot_sess *sess, int *resid)
{
	struct uio uio;
	struct mbuf *mp;
	int error;
	int flags;
	int len;

	ISBOOT_TRACE("peek BHS\n");
	if(sess->so == NULL)
		return (EINVAL);

	memset(&uio, 0, sizeof(uio));
	uio.uio_resid = sizeof(bhs_t);

	mp = NULL;
	flags = MSG_WAITALL | MSG_PEEK;
	*resid = len = uio.uio_resid;
	error = soreceive(sess->so, NULL, &uio, &mp, NULL, &flags);
	if (error) {
		if (error == EAGAIN) {
#ifdef DEBUG
			ISBOOT_ERROR("sorecv EAGAIN\n");
#endif
		} else {
			ISBOOT_ERROR("sorecv error %d\n", error);
		}
		return (error);
	}
	*resid = uio.uio_resid;
	if (uio.uio_resid == len) {
		/* EOF */
		ISBOOT_TRACE("EOF\n");
		return (EPIPE);
	}
	return (0);
}

static int
isboot_mainloop(void *arg)
{
	struct isboot_sess *sess = (struct isboot_sess *)arg;
	struct isboot_task *taskp;
	pdu_t pdu;
	int retry = 60;
	int error = 0;
	int resid;

	ISBOOT_TRACE("main loop, thread id=%x\n", curthread->td_tid);

	/* initialize session structure, mutex, etc */
	error = isboot_initialize_session(sess);
	if (error) {
		ISBOOT_ERROR("initialize error\n");
		return (error);
	}

	/* start leading connection */
	while (retry > 0) {
		error = isboot_start_session(sess);
		if (error) {
			if (retry-- >= 0) {
				ISBOOT_TRACE("boot retry (%d)\n", retry);
				tsleep(&sess->so, PSOCK, "isboot",
				    1 * hz);
				continue;
			}
			ISBOOT_ERROR("booting error\n");
			isboot_destroy_sess(sess);
			return (error);
		}
		break;
	}

	/* make sure next connection is reconnect */
	sess->reconnect = 1;

	/* create xpt path (register bus) */
	error = isboot_cam_attach(sess);
	if (error) {
		ISBOOT_ERROR("cam attach error\n");
		isboot_stop(sess);
		isboot_close(sess);
		isboot_destroy_sess(sess);
		return (error);
	}

	/* request rescan the bus */
	error = isboot_cam_rescan(sess);
	if (error) {
		ISBOOT_ERROR("cam rescan error\n");
		isboot_cam_dettach(sess);
		isboot_stop(sess);
		isboot_close(sess);
		isboot_destroy_sess(sess);
		return (error);
	}

	/* ready for doing full feature */
	ISBOOT_TRACE("going to full feature phase\n");
	for (;;) {
		/* to unload, stop request? */
		if (isboot_stop_flag != 0)
			break;

		/* first check BHS */
		error = isboot_peek_bhs(sess, &resid);
		if (error) {
			ISBOOT_TRACE("peek_bhs error=%d, state=%d/%d\n",
			    error, sess->so->so_state, sess->so->so_error);
			if (error == EAGAIN) {
				/* timeout */
				error = isboot_send_nopout(sess, &pdu, NULL);
				if (error) {
					ISBOOT_ERROR("send nopout error\n");
				}
			} else if (error == EPIPE) {
				/* EOF */
				sess->so->so_state &= ~SS_ISCONNECTED;
			}
		} else {
			if (resid != 0) {
				/* need more for BHS */
				continue;
			}
			/* at least BHS size, try to recv */
			memset(&pdu, 0, sizeof(pdu));
			ISBOOT_TRACE("recv PDU\n");
			error = isboot_recv_pdu(sess, &pdu);
			if (error) {
				isboot_free_pdu(&pdu);
				ISBOOT_ERROR("recv error!?\n");
				goto do_recovery;
			}
			error = isboot_execute(sess, &pdu);
			if (error) {
				isboot_free_pdu(&pdu);
				/* protocol error */
				goto do_recovery;
			}
			isboot_free_pdu(&pdu);
			continue;
		}

		/* link is down? */
		if ((sess->so->so_state & SS_ISCONNECTED) == 0) {
			int wait, retry;
		do_recovery:
			/* starting retry phase (session recovery) */
			ISBOOT_TRACE("socket down\n");
			wait = sess->opt.defaultTime2Wait;
			retry = 9999; /* XXX */
			error = 0;

			/* prevent next XPT */
			mtx_lock(&sess->cam_mtx);
			if (sess->cam_qfreeze == 0) {
				xpt_freeze_simq(sess->sim, 1);
				xpt_freeze_devq(sess->path, 1);
				sess->cam_qfreeze++;
			}
			mtx_unlock(&sess->cam_mtx);

			while (retry-- > 0) {
				if (isboot_stop_flag != 0) {
					error = EINTR;
					break;
				}

				/* reject running XPT */
				mtx_lock(&sess->task_mtx);
				mtx_lock(&sess->cam_mtx);
				TAILQ_FOREACH(taskp, &sess->taskq, tasks) {
					union ccb *ccb = taskp->ccb;
					if (ccb != NULL) {
						ccb->ccb_h.status
							= CAM_REQUEUE_REQ;
						ISBOOT_TRACE("xpt_done %x\n",
						    ccb->ccb_h.status);
						xpt_done(ccb);
					}
					ISBOOT_TRACE("remove ccb ITT=%x\n",
					    taskp->ITT);
					TAILQ_REMOVE(&sess->taskq, taskp,
					    tasks);
					isboot_free(taskp);
				}
				mtx_unlock(&sess->cam_mtx);
				mtx_unlock(&sess->task_mtx);

				/* stop current socket */
				ISBOOT_TRACE("stop...\n");
				error = isboot_stop(sess);
				if (error) {
					ISBOOT_ERROR("stop error\n");
					break;
				}

				/* wait for reconnecting */
				ISBOOT_TRACE("wait...(%d sec.)\n", wait);
				tsleep(&sess->so, PSOCK, "isboot",
				    wait * hz);

				/* try to reconnect */
				ISBOOT_TRACE("reconnect...\n");
				error = isboot_start_session(sess);
				if (error) {
					ISBOOT_TRACE("can't restart\n");
					if (wait == 0) {
						/* XXX nowait maybe fast? */
						ISBOOT_TRACE("force sleep "
						    "retry\n");
						tsleep(&sess->so, PSOCK,
						    "isboot", 1 * hz);
					}
					continue;
				}

				/* run frozen queue */
				mtx_lock(&sess->cam_mtx);
				xpt_release_devq(sess->path,
				    sess->cam_qfreeze, /*run_queue*/1);
				sess->cam_qfreeze = 0;
				xpt_release_simq(sess->sim, /*run_queue*/1);
				mtx_unlock(&sess->cam_mtx);

				/* request rescan the bus */
				error = isboot_cam_rescan(sess);
				if (error) {
					ISBOOT_ERROR("rescan error\n");
					continue;
				}

				/* session is restarted */
				printf("iSCSI session is restarted\n");
				error = 0;
				break;
			}
			if (isboot_stop_flag != 0)
				break;
			if (error || sess->so == NULL) {
				ISBOOT_ERROR("reconnect error!!\n");
				break;
			}
		}
	}

	/* cleanup */
	isboot_stop(sess);
	isboot_close(sess);
	isboot_cam_dettach(sess);
	isboot_destroy_sess(sess);

	ISBOOT_TRACE("main loop end\n");
	return (0);
}

static void
isboot_iscsi(void *arg)
{
	struct isboot_sess *sess = (struct isboot_sess *)arg;
	int error;

	isboot_iscsi_running = 1;
	ISBOOT_TRACE("isboot iscsi start, thread id=%x\n", curthread->td_tid);
	error = sys_setsid(curthread, NULL);
	if (error) {
		ISBOOT_ERROR("setsid error (%d)\n", error);
	}

	/* start main loop */
	error = isboot_mainloop(sess);
	if (error) {
		ISBOOT_ERROR("isboot iscsi error (%d)\n", error);
	}

	ISBOOT_TRACE("isboot iscsi end, thread id=%x\n", curthread->td_tid);
	isboot_iscsi_running = 0;
	kproc_exit(0);
}

static void
isboot_kproc(void)
{
	struct isboot_sess *sess = &isboot_g_sess;

	ISBOOT_TRACE("isboot kproc start, thread id=%x\n", curthread->td_tid);

	/* wrapper */
	isboot_iscsi(sess);

	ISBOOT_TRACE("isboot kproc end, thread id=%x\n", curthread->td_tid);
}

int
isboot_iscsi_start(void)
{
	struct isboot_sess *sess = &isboot_g_sess;
	struct kproc_desc kproc;
	int error;
	int retry;

	ISBOOT_TRACE("isboot start, thread id=%x\n", curthread->td_tid);
	memset(sess, 0, sizeof(*sess));
	sess->td = curthread;
	sess->so = NULL;
	/* build crc32c table */
	isboot_init_crc32c_table();

	/* initial task proc */
	memset(&kproc, 0, sizeof(kproc));
	kproc.arg0 = "isboot driver";
	kproc.func = isboot_kproc;
	kproc.global_procpp = &sess->pp;
	ISBOOT_TRACE("kproc_start\n");
	kproc_start(&kproc);

	printf("Attempting to login to iSCSI target and scan all LUNs.\n");
	/* wait 60 sec. for periph */
	retry = 60;
	while (sess->cam_rescan_done == 0) {
		if (isboot_stop_flag != 0)
			break;
		if (retry-- <= 0)
			break;
		tsleep(&sess->cam_rescan_done, PRIBIO, "rescan", 1 * hz);
	}
	/* setup device after the rescan is completed */
	if (sess->cam_rescan_done != 0 &&
	    sess->cam_device_installed == 0) {
		error = isboot_cam_set_devices(sess);
		if (error == 0) {
			ISBOOT_TRACE("no CAM device\n");
		} else {
			if (strlen(isboot_boot_device) != 0) {
				/* the boot device from iBFT is here */
				printf("Boot device: %s\n",
				    isboot_boot_device);
			}
			sess->cam_device_installed = 1;
			wakeup(&sess->cam_device_installed);
		}
	}
	return (0);
}

static void isboot_iscsi_device_init(void *);
SYSINIT(isboot_iscsi_device_init, SI_SUB_ROOT_CONF, SI_ORDER_ANY,
    isboot_iscsi_device_init, NULL);

static void
isboot_iscsi_device_init(void *arg)
{
	struct isboot_sess *sess = &isboot_g_sess;
	int error;

	/* valid iBFT? */
	if (ibft_get_signature() == NULL)
		return;
	/* socket is connected? */
	if (sess->so == NULL)
		return;

	/* setup device after the rescan is completed */
	if (sess->cam_rescan_done != 0 &&
	    sess->cam_device_installed == 0) {
		error = isboot_cam_set_devices(sess);
		if (error == 0) {
			ISBOOT_TRACE("no CAM device\n");
		} else {
			if (strlen(isboot_boot_device) != 0) {
				/* the boot device from iBFT is here */
				printf("Boot device: %s\n",
				    isboot_boot_device);
			}
			sess->cam_device_installed = 1;
			wakeup(&sess->cam_device_installed);
		}
	}
}
