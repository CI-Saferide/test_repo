SUMMARY = "vsentry engine"
SECTION = "vsentry engine"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://Makefile \
           file://src/main.c \
           file://../../vsentry-mod/files/tools/sr-log/include/sr_log.h \
           file://../tools/sr-log/Makefile \
           file://../tools/sr-log/src/sr_log.c \
          "

S = "${WORKDIR}"


do_compile() {
	     make
}

do_install() {
	     install -d ${D}${bindir}
	     install -m 0755 ${WORKDIR}/../build/bin/sr-engine ${D}${bindir}
}

