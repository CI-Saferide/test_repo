SUMMARY = "log output program"
SECTION = "log Engine"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://Makefile \
           file://sr_log.c \
           file://include/sr_log.h \
           file://main.c \
          "

S = "${WORKDIR}"

do_compile() {
		make
	     ${CC} main.c -static -L/${S}/ -lsr_log  -o vsentryD
}

do_install() {
	     install -d ${D}${bindir}
	     install -m 0755 vsentryD ${D}${bindir}
}
