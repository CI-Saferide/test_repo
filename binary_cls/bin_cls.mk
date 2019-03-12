ifndef TOP_DIR
TOP_DIR 	:= $(shell pwd)
endif

BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/clsbin/objs
BINDIR 		:= $(BUILD_DIR)/bin
LIBDIR 		:= $(BUILD_DIR)/lib

TARGET 		:= $(BINDIR)/vsentry_classifier
OBJS 		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
VPATH 		:= $(TOP_DIR)/classifier
INCLUDES 	:= -I/usr/include/linux/vsentry

CFLAGS 		+= -MMD -O2 -ffreestanding -fpie
CFLAGS 		+= -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs
CFLAGS 		+= -fno-strict-aliasing -fno-common -fshort-wchar
CFLAGS 		+= -Werror-implicit-function-declaration -Wno-format-security
CFLAGS 		+= -std=gnu89 -falign-jumps=1 -falign-loops=1 -funit-at-a-time
CFLAGS 		+= -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables
CFLAGS 		+= -fno-delete-null-pointer-checks -Wno-maybe-uninitialized
CFLAGS 		+= -Wframe-larger-than=1024 -fno-stack-protector
CFLAGS 		+= -Wno-unused-but-set-variable -fno-var-tracking-assignments
CFLAGS 		+= -gdwarf-4 -Wdeclaration-after-statement -Wno-pointer-sign
CFLAGS 		+= -fno-strict-overflow -fno-stack-check -fconserve-stack
CFLAGS 		+= -Werror=implicit-int -Werror=strict-prototypes

ifeq ($(DEBUG),1)
CFLAGS 		+= -DDEBUG -DCLS_DEBUG -DCAN_DEBUG -DUID_DEBUG
CFLAGS 		+= -DPROG_DEBUG -DNET_DEBUG -DHEAP_DEBUG -DPORT_DEBUG
CFLAGS 		+= -DNET_STAT_DEBUG -DIP_PROTO_DEBUG -DLEARN_DEBUG
CFLAGS 		+= -g
endif

LDFLAGS 	+= -nostdlib -Wl,--build-id=none --entry cls_handle_event \
			-T ./cls.lds

SRCS 		:= 	main.c \
			act.c \
			classifier.c \
			bitops.c \
			hash.c \
			can_cls.c \
			uid_cls.c \
			prog_cls.c \
			heap.c \
			aux.c \
			radix.c \
			net_cls.c \
			printf.c \
			port_cls.c \
			net_stat_cls.c \
			ip_proto_cls.c \
			learn.c \

OBJS 		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS 		:= $(OBJS:.o=.d)

all: $(TARGET).bin

OBJSDIR:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)
	
$(OBJDIR)/%.o: %.c Makefile
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(OBJS)
	@echo "linking $(notdir $@)"
	@$(CC) $(LDFLAGS) -o $@ $(OBJS)
	@echo "creating $(notdir $(TARGET).bin.tmp)"
	@objcopy -O binary $(TARGET) $(TARGET).bin.tmp

$(TARGET).bin: OBJSDIR $(TARGET)
	@echo "creating clean $(notdir $(TARGET).bin) size 65536"
	@$(shell dd of=$(TARGET).bin if=/dev/zero count=65536 bs=1 status=none)
	@echo "copy $(notdir $(TARGET).bin.tmp) to $(notdir $(TARGET).bin)"
	@$(shell dd of=$(TARGET).bin if=$(TARGET).bin.tmp conv=notrunc status=none)

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)
