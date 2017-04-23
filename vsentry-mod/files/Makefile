TARGET = vsentry
obj-m += $(TARGET).o 
$(TARGET)-objs := sal/platform/linux/lsm/src/sr_main.o \
				  sal/platform/linux/lsm/src/sr_netlink.o

	SRC := $(shell pwd)

EXTRA_CFLAGS := -I$(PWD)/sal/platform/linux/lsm/include

x86:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)


modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
	
    
