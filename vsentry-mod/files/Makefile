TARGET = vsentry
obj-m += $(TARGET).o 
$(TARGET)-objs := sal/platform/linux/lsm/src/module_init.o \
				  sal/platform/linux/lsm/src/sr_lsm_hooks.o \
				  multiplexer/src/multiplexer.o \
				  multiplexer/src/msg_process.o \
				  sal/platform/linux/src/sal_linux.o \

	SRC := $(shell pwd)

EXTRA_CFLAGS := -I$(PWD)/sal/platform/linux/lsm/include 
EXTRA_CFLAGS += -I$(PWD)/multiplexer/include
EXTRA_CFLAGS += -I$(PWD)/sal/include
EXTRA_CFLAGS += -I$(PWD)/sal/platform/linux/include

EXTRA_CFLAGS += -DPLATFORM_LINUX

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)

x86:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
	find . -name "*.o" -type f -delete
    
