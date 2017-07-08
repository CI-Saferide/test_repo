TARGET = vsentry
obj-m += $(TARGET).o 
$(TARGET)-objs := sal/platform/linux/src/module_init.o \
				  sal/platform/linux/lsm/src/sr_lsm_hooks.o \
				  sal/platform/linux/src/event_mediator.o \
				  sal/platform/linux/netfilter/src/sr_netfilter.o \
				  dispatcher/src/dispatcher.o \
				  dispatcher/src/msg_process.o \
				  scanner_det/src/sr_scanner_det.o \
				  classifier/src/sr_classifier.o \
				  classifier/src/sr_cls_file.o \
				  classifier/src/sr_cls_port.o \
				  tools/radix/src/sr_radix.o \
				  tools/sr-hash/src/sr_hash.o \
				  sal/platform/linux/src/sal_linux.o \
				  sal/platform/linux/src/sal_bitops_linux.o \
				  sal/src/sal_bitops.o \
				  sal/test/sal_bitops_test.o \
				  main/src/main_loop.o \
				  ../../common/src/sr_ring_buf.o \
				  sal/platform/linux/src/sal_shmem_linux.o \
				  ../../common/src/sr_msg.o \
				  ../../common/src/sr_tasks.o \

SRC := $(shell pwd)

EXTRA_CFLAGS := -I$(PWD)/sal/platform/linux/lsm/include 
EXTRA_CFLAGS += -I$(PWD)/dispatcher/include
EXTRA_CFLAGS += -I$(PWD)/classifier/include
EXTRA_CFLAGS += -I$(PWD)/scanner_det/include
EXTRA_CFLAGS += -I$(PWD)/sal/include
EXTRA_CFLAGS += -I$(PWD)/sal/test
EXTRA_CFLAGS += -I$(PWD)/sal/platform/linux/include
EXTRA_CFLAGS += -I$(PWD)/tools/sr-log/include
EXTRA_CFLAGS += -I$(PWD)/tools/radix/include
EXTRA_CFLAGS += -I$(PWD)/tools/sr-hash/include
EXTRA_CFLAGS += -I$(PWD)/../../common/include
EXTRA_CFLAGS += -I$(PWD)/main/include

#EXTRA_CFLAGS += -DUNIT_TEST

EXTRA_CFLAGS += -DPLATFORM_LINUX -D_KERNEL
#default arch is 32bit, uncomment ARCH_64 to use 64bit architectures
#EXTRA_CFLAGS += -DARCH_64

#debug flags
#EXTRA_CFLAGS += -DDEBUG_EVENT_MEDIATOR
#EXTRA_CFLAGS += -DDEBUG_DISPATCHER

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)

x86:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
arm:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -C ../../../linux-rpi M=$(PWD) modules
arm64:
	make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -C ../../../linux-rpi M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -rf ../../common/src/*.o ../../common/src/.*.cmd
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
	find . -name "*.o" -type f -delete
	find . -name "*.o.cmd" -type f -delete
    
