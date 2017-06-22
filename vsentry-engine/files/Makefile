ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET = sr-engine
obj   += $(TARGET) 
$(TARGET)-objs := $(ROOT_DIR)/src/main.o \

	SRC := $(shell pwd)

all: libsr_log.a
	arch=all
	@mkdir -p $(ROOT_DIR)/../build/bin/
	$(CC) -Wall -g sal/platform/linux/src/main.c sal/platform/linux/src/sal_shmem_linux.c src/sr_engine_main.c src/sr_cls_control.c ../../common/src/sr_msg.c ../../common/src/sr_ring_buf.c ../../common/src/sr_tasks.c -static -L$(ROOT_DIR)/../build/lib/ -I../../common/include -I$(ROOT_DIR)/include -I$(ROOT_DIR)/../../vsentry-mod/files/tools/sr-log/include/ -I$(ROOT_DIR)/sal/platform/linux/include/ -lsr_log -o $(ROOT_DIR)/../build/bin/$(TARGET) -lpthread
	
x86: libsr_log.a
	arch=x86
	@mkdir -p $(ROOT_DIR)/../build/bin/
	$(CC) -g src/main.c -static -L$(ROOT_DIR)/../build/lib/ -I$(ROOT_DIR)/../../vsentry-mod/files/tools/sr-log/include/ -lsr_log -o $(ROOT_DIR)/../build/bin/$(TARGET) -lpthread
	
arm: libsr_log.a
	arch=arm
	@mkdir -p $(ROOT_DIR)/../build/bin/
	arm-linux-gnueabi-gcc src/main.c -static -L$(ROOT_DIR)/../build/lib -I$(ROOT_DIR)/../../vsentry-mod/files/tools/sr-log/include/ -lsr_log -o $(ROOT_DIR)/../build/bin/$(TARGET) -lpthread

libsr_log.a:  
	$(MAKE) -C ../tools/sr-log $(arch) MAKEFLAGS=-I../tools/sr-log/include
	
clean:
	find ../ -name "*~" -type f -delete
	find ../ -name "*.o" -type f -delete
	rm -rf $(ROOT_DIR)/../build
	
