ifndef TOP_DIR
TOP_DIR 	:= $(shell pwd)
endif

BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/clsbin/objs
BINDIR 		:= $(BUILD_DIR)/bin
LIBDIR 		:= $(BUILD_DIR)/lib

TARGET	 	:= $(LIBDIR)/libbin_cls.a
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
CFLAGS 		+= -DDEBUG -DCLS_DEBUG -DCAN_DEBUG -DUID_DEBUG -DACT_DEBUG
CFLAGS 		+= -DPROG_DEBUG -DNET_DEBUG -DHEAP_DEBUG -DPORT_DEBUG
CFLAGS 		+= -DNET_STAT_DEBUG -DIP_PROTO_DEBUG -DLEARN_DEBUG
CFLAGS 		+= -g
endif

LDFLAGS 	+= -nostdlib -Wl,--build-id=none --entry cls_handle_event \
			-T ./cls.lds

SRCS 		:= 	main.c \
			act.c \
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
			ip_proto_cls.c \
			learn.c \
			classifier.c \

OBJS 		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS 		:= $(OBJS:.o=.d)

all: $(TARGET) $(BINDIR)/cls.bin $(BINDIR)/unit_test $(BINDIR)/unit_test2

OBJSDIR:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)
	
$(OBJDIR)/%.o: %.c Makefile
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): OBJSDIR $(OBJS)
	@echo "archiving $(notdir $@)"
	@$(AR) rcs $(TARGET) $(OBJS)

$(BINDIR)/cls:  $(OBJS)
	@echo "linking $(notdir $@)"
	@$(CC) $(LDFLAGS) -o $@ $(OBJS)
	
$(BINDIR)/cls.bin.tmp: $(BINDIR)/cls
	@echo "creating $(notdir $@)"
	@objcopy -O binary $(BINDIR)/cls $@

$(BINDIR)/cls.bin: $(TARGET) $(BINDIR)/cls.bin.tmp
	@echo "creating clean $@ size 65536"
	@$(shell dd of=$@ if=/dev/zero count=65536 bs=1 status=none)
	@echo "copy $(notdir $@.tmp) to $(notdir $@)"
	@$(shell dd of=$@ if=$@.tmp conv=notrunc status=none)

UT_CFLAGS 	+= -MMD -O0 -Wall

ifeq ($(DEBUG),1)
UT_CFLAGS 	+= -DDEBUG -DCLS_DEBUG -DCAN_DEBUG -DUID_DEBUG -DACT_DEBUG
UT_CFLAGS 	+= -DPROG_DEBUG -DNET_DEBUG -DHEAP_DEBUG -DPORT_DEBUG
UT_CFLAGS 	+= -DNET_STAT_DEBUG -DIP_PROTO_DEBUG -DLEARN_DEBUG
UT_CFLAGS 	+= -g
endif

$(BINDIR)/unit_test: OBJSDIR
	@echo "linking $(notdir $@)"
	$(CC) $(UT_CFLAGS) $(INCLUDES) $(notdir $@).c -o $@
	
$(BINDIR)/unit_test2: OBJSDIR
	@echo "linking $(notdir $@)"
	$(CC) $(UT_CFLAGS) $(INCLUDES) $(notdir $@).c -o $@

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)