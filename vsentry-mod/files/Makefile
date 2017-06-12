TARGET = vsentry
obj-m += $(TARGET).o 
$(TARGET)-objs := sal/platform/linux/src/module_init.o \
				  sal/platform/linux/lsm/src/sr_lsm_hooks.o \
				  sal/platform/linux/netfilter/src/sr_netfilter.o \
				  multiplexer/src/multiplexer.o \
				  multiplexer/src/msg_process.o \
				  classifier/src/sr_classifier.o \
				  tools/radix/src/sr_radix.o \
				  sal/platform/linux/src/sal_linux.o \
				  sal/platform/linux/src/sal_bitops_linux.o \
				  sal/src/sal_bitops.o \
				  sal/test/sal_bitops_test.o \

	SRC := $(shell pwd)

EXTRA_CFLAGS := -I$(PWD)/sal/platform/linux/lsm/include 
EXTRA_CFLAGS += -I$(PWD)/multiplexer/include
EXTRA_CFLAGS += -I$(PWD)/classifier/include
EXTRA_CFLAGS += -I$(PWD)/sal/include
EXTRA_CFLAGS += -I$(PWD)/sal/test
EXTRA_CFLAGS += -I$(PWD)/sal/platform/linux/include
EXTRA_CFLAGS += -I$(PWD)/tools/sr-log/include
EXTRA_CFLAGS += -I$(PWD)/tools/radix/include

#EXTRA_CFLAGS += -DUNIT_TEST
EXTRA_CFLAGS += -DPLATFORM_LINUX -D_KERNEL

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)

x86:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
arm:
	make ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- -C ../../../linux-rpi M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
	find . -name "*.o" -type f -delete
	find . -name "*.o.cmd" -type f -delete
	
    
