DESCRIPTION = "vsenstry kernel module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=12f884d2ae1ff87c09e5b7ccc2c4ca7e"

inherit module

PR = "r0"
PV = "0.1"

SRC_URI = "file://Makefile \
		   file://sal/platform/linux/src/sal_linux.c \
		   file://sal/include/sr_sal.h \
		   file://sal/platform/linux/include/sal_linux.h \
           file://sal/platform/linux/lsm/src/module_init.c \
           file://sal/platform/linux/lsm/src/sr_netlink.c \
           file://sal/platform/linux/lsm/include/sr_netlink.h \
           file://sal/platform/linux/lsm/include/sr_lsm_hooks.h \
           file://sal/platform/linux/lsm/src/sr_lsm_hooks.c \
           file://multiplexer/src/multiplexer.c \
           file://multiplexer/include/multiplexer.h \
           file://COPYING \
          "

S = "${WORKDIR}"

