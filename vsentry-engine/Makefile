ifdef CROSS_COMPILE
export CC=$(CROSS_COMPILE)gcc
endif


TOP_DIR		:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR		:= $(BUILD_DIR)/objs
LIBDIR		:= $(BUILD_DIR)/lib
BINDIR 		:= $(BUILD_DIR)/bin

TARGET 		:= sr_engine

# where to search for sources
VPATH 		:=  $(TOP_DIR)/sal/platform/linux/src \
				$(TOP_DIR)/src \
				$(TOP_DIR)/../common/src \	

# sources to compile
SRCS 		:=  main.c \
				sal_shmem_linux.c \
				sal_linux.c \
				sr_cls_file_control.c \
				sr_cls_network_control.c \
				sr_cls_canbus_control.c \
				sr_ml_conngraph.c \
				sr_cls_uid_control.c \
				sr_radix.c \
				sr_cls_port_control.c \
				sr_cls_rules_control.c \
				sr_msg.c \
				sr_ring_buf.c \
				sr_tasks.c \
				sr_event_receiver.c \
				sr_engine_main.c \
				sr_config.c \
				sr_cli.c \

# include folders
INCLUDES 	:=  -I../common/include \
				-Iinclude \
				-I$(TOP_DIR)/../tools/radix/include \
				-Isal/platform/linux/include \
				-I../tools/sr-log/include

OBJS		:=  $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:=  $(OBJS:.o=.d)

# libs to link with
LIBS		:= -lpthread -lsr_log
# and where to search them 
LIB_PATH 	:= -L$(LIBDIR)

CFLAGS 		+= -MMD -Wall

#CFLAGS 		+= -DSR_RB_DEBUG -DSR_MSG_DEBUG

ifdef DEBUG
CFLAGS		+= -g -O0
else
CFLAGS 		+= -O2
endif

all: $(TARGET)

$(TARGET): $(OBJDIR) $(OBJS) libsr_log
	@echo "linking $(notdir $@)"
	@$(CC) $(OBJS) -o $(BINDIR)/$(TARGET) $(LIB_PATH) $(LIBS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)
	@mkdir -p $(BINDIR)

libsr_log:
	@$(MAKE) -s -C ../tools/sr-log TOP_DIR=$(TOP_DIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)


