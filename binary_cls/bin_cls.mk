ifndef TOP_DIR
TOP_DIR 	:= $(shell pwd)
endif

ifndef OBJCOPY
OBJCOPY        := objcopy
endif

BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/clsbin/objs
BINDIR 		:= $(BUILD_DIR)/bin
LIBDIR 		:= $(BUILD_DIR)/lib

TARGET	 	:= $(BINDIR)/cls.bin
OBJS 		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
VPATH 		:= $(TOP_DIR)/classifier

SRCS 		:= 	main.c \
				act.c \
				classifier.c \
				bitops.c \
				heap.c \
				hash.c \
				str_tree.c \
				aux.c \
				uid_cls.c \
				prog_cls.c \
				can_cls.c \
				radix.c \
				net_cls.c \
				ip_proto_cls.c \
				port_cls.c \
				file_cls.c \
				printf.c \
				lru_cache.c \

ifeq ($(ENABLE_LEARN),1)
SRCS 			+= learn.c
endif

OBJS 		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS 		:= $(OBJS:.o=.d)

all: $(TARGET)

# common cflags for all platforms (x86-32/64, arm32/64) to compile
# both the binary classifier and the unitests programs (they need to be aligned)
# those flags are taken from kernel compilation since the binary classifier is
# running as part of the kernel execution env, it need to be aligned with the
# flags the kernel uses.
CFLAGS 		+= -O2 -MMD -ffreestanding -fpie
CFLAGS 		+= -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs
CFLAGS 		+= -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration
CFLAGS 		+= -Wno-format-security -std=gnu89 -fno-delete-null-pointer-checks
CFLAGS 		+= -Wframe-larger-than=1024 -fno-stack-protector
CFLAGS 		+= -Wno-unused-but-set-variable
CFLAGS 		+= -Wno-pointer-sign -Werror=implicit-int -Wdeclaration-after-statement
CFLAGS 		+= -fno-strict-overflow -fconserve-stack -fno-var-tracking-assignments
CFLAGS 		+= -fno-asynchronous-unwind-tables -fno-stack-check -fshort-wchar

# additional common cflags if debug is enabled
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -DCLS_DEBUG -DCAN_DEBUG -DUID_DEBUG -DACT_DEBUG
CFLAGS += -DPROG_DEBUG -DNET_DEBUG -DHEAP_DEBUG -DPORT_DEBUG -DFILE_DEBUG
CFLAGS += -DNET_STAT_DEBUG -DIP_PROTO_DEBUG -DLEARN_DEBUG -DSTR_TREE_DEBUG
CFLAGS += -g
endif

# binary classifier specific ldflags
CLS_LDFLAGS += -nostartfiles -lgcc -fpie -Wl,--build-id=none --entry cls_handle_event \
				-T ./cls.lds

# detect if target is ARMv7
ARM_ARCH 	= $(shell $(CC) -dM -E -< /dev/null | grep "__ARM_ARCH " | awk {'printf $$3'})
ifeq ($(ARM_ARCH),7)
# ARMv7 (32 bit) additional common cflags. in this case the flags
# are the same for binary classifier and unitests programs
CFLAGS 		+= -DARM7DIV -marm -mno-thumb-interwork -mfpu=vfp
LDFLAGS 	+= -Wl,-no-wchar-size-warning
OBJS 		+= $(OBJDIR)/div.o
endif

# detect if target is i386
X86_ARCH 	= $(shell $(CC) -dM -E -< /dev/null | grep " i386 " | awk {'printf $$2'})
ifeq ($(X86_ARCH),i386)
# i386 (32 bit) classifier binary cflags.
# should not be used for unitest programs !!!. for some reason
# the way user space is compiled is not the same as kernel.
CFLAGS += -m32 -mregparm=3 -freg-struct-return -msoft-float
CFLAGS += -march=i686 -mtune=generic -maccumulate-outgoing-args -Wa,-mtune=generic32
endif

ifeq ($(ENABLE_LEARN),1)
CFLAGS 		+= -DENABLE_LEARN
endif

OBJSDIR:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)
	
$(OBJDIR)/%.o: %.c Makefile
	@echo "compiling $(notdir $<)"
	@$(CC) $(ARCH_CFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR)/%.o: %.S Makefile
	@echo "compiling $(notdir $<)"
	@$(CC) $(ARCH_CFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BINDIR)/cls: OBJSDIR $(OBJS)
	@echo "linking $(notdir $@)"
	@$(CC) $(CLS_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS)

$(BINDIR)/cls.bin.tmp: $(BINDIR)/cls
	@echo "creating $(notdir $@)"
	@$(OBJCOPY) -O binary $(BINDIR)/cls $@

$(TARGET): $(BINDIR)/cls.bin.tmp
	@echo "creating clean $@ size 131072"
	@$(shell dd of=$@ if=/dev/zero count=131072 bs=1 status=none)
	@echo "copy $(notdir $@.tmp) to $(notdir $@)"
	@$(shell dd of=$@ if=$@.tmp conv=notrunc status=none)

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)
