KERNEL_SRC  ?= /lib/modules/$(shell uname -r)/build

#make ARCH=arm64 KERNEL_SRC=~/git/raspberrypi/linux CROSS_COMPILE=aarch64-linux-gnu-

# NOTE: if you would like to compile the code with a different kernel 
#		from the default please specify its location:
#		KERNEL_SRC=/PATH/TO/KERNEL
#
#		if you would like to cross compile please specify the cross compiler prefix
#		and the arch:
#		ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
#		example for arm64 & new kernel source location:
#		make ARCH=arm64 KERNEL_SRC=~/git/raspberrypi/linux CROSS_COMPILE=aarch64-linux-gnu- 

all:
	@$(MAKE) -s -C vsentry-engine
	@$(MAKE) -C vsentry-mod KERNEL_SRC=${KERNEL_SRC}

clean:
	@$(MAKE) -s -C vsentry-engine clean
	@$(MAKE) -C vsentry-mod clean
