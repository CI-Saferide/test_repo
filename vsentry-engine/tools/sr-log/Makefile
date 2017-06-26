ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET = libsr_log
obj   += $(TARGET).a
$(TARGET)-objs := src/sr_log.o \
				  $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux.o \

	SRC := $(shell pwd)
	
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../files/sal/platform/linux/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include
EXTRA_CFLAGS +=	-lpthread
EXTRA_CFLAGS += -DPLATFORM_LINUX
EXTRA_CFLAGS += -g

all:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
	$(CC) -Wall -g -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -I$(ROOT_DIR)/../../files/sal/platform/linux/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/include \
		  -I../../../common/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o sal_linux.o
	
x86:
	@mkdir -Wall -p $(ROOT_DIR)/../../build/lib/
	$(CC) -g -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -I$(ROOT_DIR)/../../files/sal/platform/linux/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/include \
		  -I../../../common/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o sal_linux.o

arm:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
	arm-linux-gnueabi-gcc -Wall -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -I$(ROOT_DIR)/../../files/sal/platform/linux/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/include \
		  -I../../../common/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o sal_linux.o
	
libsr_log.a: sr_log.o sal_linux.o
	$(AR) rcs $(ROOT_DIR)/../../build/libsr_log.a sr_log.o sal_linux.o

clean:
	rm -f $(ROOT_DIR)/../../build/lib/libsr_log.a
	find . -name "*.o" -type f -delete
	find ../ -name "*~" -type f -delete
	
	



