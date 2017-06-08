ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET = libsr_log
obj   += $(TARGET).a
$(TARGET)-objs := src/sr_log.o \
				  $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux_engine.o \

	SRC := $(shell pwd)
	
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../files/sal/platform/linux/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/include
EXTRA_CFLAGS += -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include
EXTRA_CFLAGS +=	-lpthread
EXTRA_CFLAGS += -DPLATFORM_LINUX

all:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
	$(CC) -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -I$(ROOT_DIR)/../../files/sal/platform/linux/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux_engine.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o sal_linux_engine.o
	
x86:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
	$(CC) -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -I$(ROOT_DIR)/../../files/sal/platform/linux/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux_engine.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o sal_linux_engine.o

arm:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
	arm-linux-gnueabi-gcc -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -I$(ROOT_DIR)/../../files/sal/platform/linux/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/sal/include \
		  -I$(ROOT_DIR)/include \
		  -I$(ROOT_DIR)/../../../vsentry-mod/files/tools/sr-log/include \
		  -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c $(ROOT_DIR)/../../files/sal/platform/linux/src/sal_linux_engine.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o sal_linux_engine.o
	
libsr_log.a: sr_log.o sal_linux_engine.o
	$(AR) rcs $(ROOT_DIR)/../../build/libsr_log.a sr_log.o sal_linux_engine.o

clean:
	rm -f $(ROOT_DIR)/../../build/lib/libsr_log.a
	find . -name "*.o" -type f -delete
	find ../ -name "*~" -type f -delete
	
	



