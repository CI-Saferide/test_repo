ifndef TOP_DIR
TOP_DIR 	:= $(shell pwd)
endif
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR 		:= $(BUILD_DIR)/objs
LIBDIR 		:= $(BUILD_DIR)/lib

TARGET 		:= libsysrepo_mng
VPATH 		:= ./src
SRCS 		:= sysrepo_mng.c \

INCLUDES	:= -I$(shell pwd)/include \
			   -I$(TOP_DIR)/../common/include \
			   -I$(TOP_DIR)/../tools/sr-log/include \
			   -I$(TOP_DIR)/../tools/json \
			   -I$(TOP_DIR)/sal/platform/linux/include \
			   -I$(TOP_DIR)/../vsentry-lib/include \


OBJS 		:= $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS 		:= $(OBJS:.o=.d)

CFLAGS += -MMD -Wall -g
CFLAGS += $(if $(NO_CEF),-DNO_CEF)

all: $(TARGET)

$(TARGET): $(OBJDIR) $(OBJS)
	@echo "archiving $(notdir $@)"
	@$(AR) rcs $(LIBDIR)/$(TARGET).a $(OBJS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $@)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

-include $(DEPS)

