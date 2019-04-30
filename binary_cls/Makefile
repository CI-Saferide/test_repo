ifndef TOP_DIR
TOP_DIR 	:= $(shell pwd)
endif

BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/cls/objs
BINDIR 		:= $(BUILD_DIR)/bin
LIBDIR 		:= $(BUILD_DIR)/lib

TARGET	 	:= $(LIBDIR)/libbin_cls.a
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

all: bincls $(TARGET)

.PHONY: bincls
bincls:
	$(MAKE) -f bin_cls.mk DEBUG=$(DEBUG)

# common cflags for all platforms (x86-32/64, arm32/64) to compile
# both the binary classifier and the unitests programs (they need to be aligned)
# those flags are taken from kernel compilation since the binary classifier is
# running as part of the kernel execution env, it need to be aligned with the
# flags the kernel uses.
CFLAGS 		+= -MMD -ffreestanding -fpie
CFLAGS 		+= -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs
CFLAGS 		+= -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration
CFLAGS 		+= -Wno-format-security -std=gnu89 -fno-delete-null-pointer-checks
CFLAGS 		+= -fno-stack-protector
CFLAGS 		+= -Wno-unused-but-set-variable
CFLAGS 		+= -Wno-pointer-sign -Werror=implicit-int -Wdeclaration-after-statement
CFLAGS 		+= -fno-strict-overflow -fconserve-stack -fno-var-tracking-assignments
CFLAGS 		+= -fno-asynchronous-unwind-tables -fno-stack-check -fshort-wchar

# additional common cflags if debug is enabled
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -DCLS_DEBUG -DCAN_DEBUG -DUID_DEBUG -DACT_DEBUG
CFLAGS += -DPROG_DEBUG -DNET_DEBUG -DHEAP_DEBUG -DPORT_DEBUG -DFILE_DEBUG
CFLAGS += -DNET_STAT_DEBUG -DIP_PROTO_DEBUG -DLEARN_DEBUG -DSTR_TREE_DEBUG
CFLAGS += -g -O0
else
CFLAGS += -O2
endif

# detect if target is ARMv7
ARM_ARCH 	= $(shell $(CC) -dM -E -< /dev/null | grep "__ARM_ARCH " | awk {'printf $$3'})
ifeq ($(ARM_ARCH),7)
# ARMv7 (32 bit) additional common cflags. in this case the flags
# are the same for binary classifier and unitests programs
CFLAGS 		+= -marm
LDFLAGS 	+= -Wl,-no-wchar-size-warning
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
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): OBJSDIR $(OBJS)
	@echo "archiving $(notdir $@)"
	@$(AR) rcs $@ $(OBJS)

.PHONY: unitests

unitests: $(TARGET)
	@echo "linking unit_test_db"
	@$(CC) $(CFLAGS) $(INCLUDES) unit_test_db.c -o $(BINDIR)/unit_test_db $(LDFLAGS) -L$(LIBDIR) -lbin_cls
	@echo "linking unit_test_drv"
	@$(CC) $(CFLAGS) $(INCLUDES) unit_test_drv.c -o $(BINDIR)/unit_test_drv $(LDFLAGS) -L$(LIBDIR) -lbin_cls
	@echo "linking unit_test_ba"
	@$(CC) $(CFLAGS) $(INCLUDES) unit_test_ba.c -o $(BINDIR)/unit_test_ba $(LDFLAGS) -L$(LIBDIR) -lbin_cls

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)
