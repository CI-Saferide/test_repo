TARGET = vsentry
obj-m += $(TARGET).o 
$(TARGET)-objs := sr_main.o \
				  sr_netlink.o

	SRC := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC)
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
	
    
