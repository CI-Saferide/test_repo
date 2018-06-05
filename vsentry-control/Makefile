ifdef CROSS_COMPILE
export CC=$(CROSS_COMPILE)gcc
endif

TOP_DIR		:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR		:= $(BUILD_DIR)/objs
BINDIR 		:= $(BUILD_DIR)/bin

CPPFLAGS += -Iinclude
CONTROL_TOOL = $(BINDIR)/vsentry-ctrl

all: $(CONTROL_TOOL)

CONTROL_TOOL_SRCS = control_cmd.c 
CONTROL_TOOL_OBJS = $(addprefix $(OBJDIR)/,$(CONTROL_TOOL_SRCS:.c=.o))

$(CONTROL_TOOL): $(OBJDIR) $(CONTROL_TOOL_OBJS)
	$(CC) $(CPPFALGS) $(CFLAGS) $(CONTROL_TOOL_OBJS) $(LDFLAGS) -o $@

print-%:
	@echo $* = $($*)

$(CONTROL_TOOL_OBJS): $(CONTROL_TOOL_SRCS)
	$(CC) -c $(CPPFLAGS) $^ -o $@

# where to search for sources
VPATH 		:= src 	

# include folders
INCLUDES 	:=  -Iinclude \
				-Isal/platform/linux/include \

#DEPS		:=  $(OBJS:.o=.d)

# libs to link with
LIBS		:= 
# and where to search them 
LIB_PATH 	:= 

CFLAGS 		+= -Wall

#CFLAGS 		+= -DSR_RB_DEBUG -DSR_MSG_DEBUG

ifdef DEBUG
CFLAGS		+= -g -O0
else
CFLAGS 		+= -O2
endif

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

#-include $(DEPS)


