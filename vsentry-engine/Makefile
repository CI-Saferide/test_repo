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
				$(TOP_DIR)/stat_analysis/src \
				$(TOP_DIR)/db/src

# sources to compile
SRCS 		:=  main.c \
				sal_shmem_linux.c \
				sal_linux.c \
				sal_can_linux.c \
				sr_cls_file_control.c \
				sr_cls_network_control.c \
				sr_cls_canbus_control.c \
				sr_ml_conngraph.c \
				sr_cls_uid_control.c \
				sr_radix.c \
				sr_file_hash.c \
				sr_cls_port_control.c \
				sr_cls_rules_control.c \
				sr_msg.c \
				sr_ring_buf.c \
				sr_tasks.c \
				sr_engine_utils.c \
				sr_event_receiver.c \
				sr_event_stats_receiver.c \
				sr_engine_main.c \
				sr_config.c \
				sr_cli.c \
				sr_db.c \
				sr_control.c \
				sr_can_collector.c \
				sr_config_parse.c \
				sr_stat_process_connection.c \
				sr_stat_learn_rule.c \
				sr_static_policy.c \
				sr_command.c \
				sr_stat_analysis.c \
				sr_cyclic_array.c \
				sr_info_gather.c \
				sr_db_ip.c \
				sr_db_file.c \
				sr_db_can.c \
				sr_ml_can.c \
                log_uploader.c


# include folders
INCLUDES 	:=  -I../common/include \
				-Iinclude \
				-I$(TOP_DIR)/../tools/radix/include \
				-Isal/platform/linux/include \
				-Isal/include \
				-I../tools/sr-log/include \
				-I../tools/sr-hash/include \
				-I../tools/json \
				-I../tools/sysrepo_mng/include \
				-I../vsentry-lib/include \
				-I../common/stat_analysis/include \
				-Istat_analysis/include \
				-Idb/include \

OBJS		:=  $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:=  $(OBJS:.o=.d)

# libs to link with
LIBS		:= -lpthread -lsr_log -lsr_hash -lsysrepo_mng -ljsmn -lsentry -lsysrepo -lcurl -larchive -lcrypto
# and where to search them 
LIB_PATH 	:= -L$(LIBDIR) -L../vsentry-lib/lib

CFLAGS 		+= -MMD -Wall
CFLAGS 		+= -DCONFIG_STAT_ANALYSIS
CFLAGS 		+= -DCONFIG_CAN_ML
CFLAGS 		+= $(if $(SR_STAT_ANALYSIS_DEBUG),-DSR_STAT_ANALYSIS_DEBUG)
CFLAGS 		+= $(if $(SR_CAN_DEBUG_PRINT),-DSR_CAN_DEBUG_PRINT)

CFLAGS 		+= -DSR_CAN_DEBUG_PRINT
#CFLAGS 		+= -DSR_RB_DEBUG -DSR_MSG_DEBUG
CFLAGS 		+= -D__linux
#CFLAGS 		+= -DUNIT_TEST

ifdef DEBUG
CFLAGS		+= -g -O0
else
CFLAGS 		+= -O2
endif

all: $(TARGET)

build_ver:
	@echo "static const char SR_GIT_BUILD[] = \"`git log --pretty=format:'%h' -n 1`\"; " > $(TOP_DIR)/../common/include/sr_build_ver.h

$(TARGET): build_ver $(OBJDIR) $(OBJS) libsr_log libsr_hash libjsmn libsysrepo_mng
	@echo "linking $(notdir $@)"
	@$(CC) $(LDFLAGS) $(OBJS) -o $(BINDIR)/$(TARGET) $(LIB_PATH) $(LIBS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)
	@mkdir -p $(BINDIR)

libsr_log:
	@$(MAKE) -s -C ../tools/sr-log TOP_DIR=$(TOP_DIR)

libsr_hash:
	@$(MAKE) -s -C ../tools/sr-hash TOP_DIR=$(TOP_DIR)

libjsmn:
	@$(MAKE) -s -C ../tools/json TOP_DIR=$(TOP_DIR)

libsysrepo_mng:
	@$(MAKE) -s -C ../tools/sysrepo_mng TOP_DIR=$(TOP_DIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

SPLINT_FLAGS += -warnposix -paramuse -unrecog -retvalint -boolops -predboolothers -mustfreefresh -retvalother
SPLINT_FLAGS += -mustfreeonly -predboolint -nullpass
splint_analysis:
	@$(foreach SRC,$(shell find . -name "*.c"),splint $(SPLINT_FLAGS) $(INCLUDES) $(SRC);)

-include $(DEPS)


