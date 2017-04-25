ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET = libsr_log
obj   += $(TARGET).a
$(TARGET)-objs := src/sr_log.o \

	SRC := $(shell pwd)

all:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
#$(CC) -lm -o sr_log -L. -lsr_log
	$(CC) -I$(ROOT_DIR)/include -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o

x86:
	@mkdir -p $(ROOT_DIR)/../../build/lib/
	$(CC) -I$(ROOT_DIR)/include -DPLATFORM_LINUX -O -c -static $(ROOT_DIR)/src/sr_log.c
	$(AR) rcs $(ROOT_DIR)/../../build/lib/libsr_log.a sr_log.o

libsr_log.a: sr_log.o
	$(AR) rcs $(ROOT_DIR)/../../build/libsr_log.a sr_log.o

clean:
	rm -f $(ROOT_DIR)/../../build/lib/libsr_log.a
