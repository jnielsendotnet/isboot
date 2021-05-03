# Makefile isboot.ko

KMOD=	isboot
SRCS=	isboot.c ibft.c iscsi.c
SRCS+=	isboot.h ibft.h iscsi_compat.h
SRCS+=	opt_cam.h device_if.h bus_if.h
#CFLAGS+= -DVIMAGE
CFLAGS+= -DIBFT_VERBOSE
#CFLAGS+= -DDEBUG
#CFLAGS+= -DISBOOT_OPT_PREFERRED_HEADER_DIGEST
#CFLAGS+= -DISBOOT_OPT_PREFERRED_DATA_DIGEST

EXPORT_SYMS=	ibft_get_signature	\
		ibft_get_nic0_mac	\
		ibft_get_initiator	\
		ibft_get_nic0		\
		ibft_get_target0	\
		ibft_get_nic1		\
		ibft_get_target1	\
		isboot_get_boot_nic	\
		isboot_get_boot_device

.include <bsd.kmod.mk>
