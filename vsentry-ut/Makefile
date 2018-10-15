ifdef CROSS_COMPILE
export CC=$(CROSS_COMPILE)gcc
endif

TOP_DIR		:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR		:= $(BUILD_DIR)/objs
LIBDIR		:= $(BUILD_DIR)/lib
BINDIR 		:= $(BUILD_DIR)/bin

TARGET 		:= sr_test

# where to search for sources
VPATH 		:=  $(TOP_DIR)/sal/platform/linux/src \
				$(TOP_DIR)/src \
				$(TOP_DIR)/../common/src \

# sources to compile
SRCS 		:=  main.c \

# include folders
INCLUDES 	:=  -I../common/include \
				-Iinclude \
				-I../tools/json \
				-I../tools/sysrepo_mng/include \
				-I../vsentry-lib/include \

OBJS		:=  $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:=  $(OBJS:.o=.d)

# libs to link with
LIBS		:= -lpthread -lsysrepo_mng -ljsmn -lsentry -lsysrepo -ldb_tools
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
LDFLAGS += -lpthread
TARGET_SYSTEM_TEST = $(BINDIR)/system_test_process

all: $(TARGET) $(TARGET_SYSTEM_TEST)

$(TARGET): $(OBJDIR) $(OBJS) libjsmn libsysrepo_mng libdb_tools
	@echo "linking $(notdir $@)"
	$(CC) $(OBJS) -o $(BINDIR)/$(TARGET) $(LIB_PATH) $(LIBS) $(LDFLAGS)

$(TARGET_SYSTEM_TEST): system_test_process.c
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)
	@mkdir -p $(BINDIR)

libjsmn:
	@$(MAKE) -s -C ../tools/json TOP_DIR=$(TOP_DIR)

libsysrepo_mng:
	@$(MAKE) -s -C ../tools/sysrepo_mng NO_CEF=1 TOP_DIR=$(TOP_DIR)

libdb_tools:
	@$(MAKE) -s -C ../tools/db_tools NO_CEF=1 TOP_DIR=$(TOP_DIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	$(CC) $(CFLAGS) $(INCLUDES) -g -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)


