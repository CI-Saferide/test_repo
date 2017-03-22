#
# This file was derived from the 'Hello World!' example recipe in the
# Yocto Project Development Manual.
#

SUMMARY = "Simple helloworld application"
SECTION = "examples"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://vsentryCPU.c"

S = "${WORKDIR}"

do_compile() {

	     ${CC} vsentryCPU.c -o vsentryCPU
}

do_install() {
	     install -d ${D}${bindir}
	     install -m 0755 vsentryCPU ${D}${bindir}
}
