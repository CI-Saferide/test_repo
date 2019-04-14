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
#  SR_STAT_ANALYSIS_DEBUG=y - set stat analysis debug flag

ENG_FLAGS += $(if $(SR_CLI),SR_CLI=1)
ENG_FLAGS += $(if $(IRDETO),IRDETO=1)
MORE_TARGETS += $(if $(SR_CLI),cli)
MORE_CLEAN_TARGETS += $(if $(SR_CLI),clean_cli)

all: $(MORE_TRAGETS)
	@echo "***** enter vsentry-mod *****"
	@$(MAKE) -C vsentry-mod KERNEL_SRC=${KERNEL_SRC}
	@echo "***** enter vsentry-engine *****"
	@$(MAKE) -s -C vsentry-engine $(ENG_FLAGS)
	@echo "***** enter vsentry-cli *****"
	@$(MAKE) -s -C vsentry-cli
	@echo "***** enter vsentry-ut *****"
	@$(MAKE) -s -C vsentry-ut

clean: $(MORE_CLEAN_TARGETS)
	@$(MAKE) -C vsentry-mod clean
	@$(MAKE) -s -C vsentry-engine clean
	@$(MAKE) -s -C vsentry-cli clean
	@$(MAKE) -s -C vsentry-ut clean

install:
	make install -s -C vsentry-mod
	make install -s -C vsentry-engine
	make install -s -C vsentry-cli
