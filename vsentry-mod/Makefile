EXTRA_CFLAGS += -I$(TOP_DIR)/sal/platform/linux/lsm/include 
EXTRA_CFLAGS += -I$(TOP_DIR)/multiplexer/include
EXTRA_CFLAGS += -I$(TOP_DIR)/classifier/include
EXTRA_CFLAGS += -I$(TOP_DIR)/sal/include
EXTRA_CFLAGS += -I$(TOP_DIR)/sal/test
EXTRA_CFLAGS += -I$(TOP_DIR)/sal/platform/linux/include
EXTRA_CFLAGS += -I$(TOP_DIR)/../tools/sr-log/include
EXTRA_CFLAGS += -I$(TOP_DIR)/../tools/radix/include
EXTRA_CFLAGS += -I$(TOP_DIR)/../tools/sr-hash/include
EXTRA_CFLAGS += -I$(TOP_DIR)/../common/include
EXTRA_CFLAGS += -I$(TOP_DIR)/main/include
EXTRA_CFLAGS += -I$(TOP_DIR)/../tools/sr-log/include
EXTRA_CFLAGS += -I$(TOP_DIR)/dispatcher/include
EXTRA_CFLAGS += -I$(TOP_DIR)/scanner_det/include

#EXTRA_CFLAGS += -DUNIT_TEST
#EXTRA_CFLAGS += -D_KERNEL
#debug flags
#EXTRA_CFLAGS += -DDEBUG_EVENT_MEDIATOR
#EXTRA_CFLAGS += -DDEBUG_DISPATCHER
#EXTRA_CFLAGS += -DSR_MSG_DEBUG
#EXTRA_CFLAGS += -DSR_RB_DEBUG
#EXTRA_CFLAGS += -DDEBUG_NETWORK

ifneq ($(KERNELRELEASE),)

TARGET = vsentry
obj-m += $(TARGET).o 
$(TARGET)-objs := sal/platform/linux/src/module_init.o \
				  sal/platform/linux/lsm/src/sr_lsm_hooks.o \
				  sal/platform/linux/src/event_mediator.o \
				  sal/platform/linux/netfilter/src/sr_netfilter.o \
				  dispatcher/src/dispatcher.o \
				  dispatcher/src/msg_process.o \
				  scanner_det/src/sr_scanner_det.o \
				  classifier/src/sr_cls_network.o \
				  classifier/src/sr_classifier.o \
				  classifier/src/sr_cls_file.o \
				  classifier/src/sr_cls_port.o \
				  classifier/src/sr_cls_canid.o \
				  ../tools/radix/src/sr_radix.o \
				  ../tools/sr-hash/src/sr_hash.o \
				  sal/platform/linux/src/sal_linux.o \
				  sal/platform/linux/src/sal_bitops_linux.o \
				  sal/src/sal_bitops.o \
				  sal/test/sal_bitops_test.o \
				  main/src/main_loop.o \
				  ../common/src/sr_ring_buf.o \
				  sal/platform/linux/src/sal_shmem_linux.o \
				  ../common/src/sr_msg.o \
				  ../common/src/sr_tasks.o \

else

KERNEL_SRC  ?= /lib/modules/$(shell uname -r)/build
PWD         := $(shell pwd)

all:
	@$(MAKE) -C $(KERNEL_SRC) M=$(PWD) TOP_DIR=$(PWD) modules

endif

clean:
	@$(MAKE) -s -C $(KERNEL_SRC) M=$(PWD) clean
	@rm -fr ../common/src/*.o
	@rm -fr ../common/src/.*.o.cmd
	@rm -fr ../tools/sr-hash/src/*.o
	@rm -fr ../tools/sr-hash/src/.*.o.cmd
	@rm -fr ../tools/radix/src/*.o
	@rm -fr ../tools/radix/src/.*.o.cmd

modules_install:
	@$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules_install

depend .depend dep:
	@$(CC) $(EXTRA_CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif

