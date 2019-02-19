TOP_DIR	 	:=  $(shell pwd)
BUILD_DIR 	:=  $(TOP_DIR)/build
OBJDIR 		:=  $(BUILD_DIR)/objs
BINDIR 		:=  $(BUILD_DIR)/bin
LIBDIR 		:=  $(BUILD_DIR)/lib

TARGET 		:=  libclient
SRCS 		:=  vproxy_client.c

LIBS 		:=  -lpthread
CFLAGS 		+=  -MMD -Wall -I../tools/sr-log/include -I../common/include -I../vsentry-engine/sal/platform/linux/include

ifeq ($(XCODE), 1)
CLOAKED 	= $(patsubst %.c,%.cloak.c,$(SRCS))
TRANSCODER_DIALECT = gcc_x64
XCLOAK 		:= $(CW_CSP_HOME)/bin/xcode
NAILS 		:=-auto_transforms off -transform_type_mapping blue Finite 7F0C111D09C4FB861118105D7E3ABC8A \
			-transform_type_mapping red Finite 7F0C111D09C4FB861118105D7E3ABC8A
OBJS 		:=  $(addprefix $(OBJDIR)/,$(CLOAKED:.c=.o))
else
OBJS 		:=  $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
endif
DEPS 		:=  $(OBJS:.o=.d)

ifdef DEBUG
CFLAGS 		+=  -g -O0 -DDEBUG
else
CFLAGS 		+=  -O2
endif

all: $(TARGET)

$(TARGET): $(OBJDIR) $(OBJS) $(CLOAKED)
	@echo "linking $(notdir $@)"
	@$(AR) rcs $(LIBDIR)/$(TARGET).a $(OBJS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

ifeq ($(XCODE), 1)
$(CLOAKED): $(SRCS)
	@echo "cloaking $^"
ifdef DEBUG
	@$(XCLOAK) -I../include -reset -DDEBUG -D__CS_POSIX_IS_REQUIRED -compiler $(TRANSCODER_DIALECT) $(NAILS) $^
else
	@$(XCLOAK) -I../include -reset -D__CS_POSIX_IS_REQUIRED -compiler $(TRANSCODER_DIALECT) $(NAILS) $^
endif
endif

client: $(TARGET) $(OBJDIR)/client.o
	@echo "linking $(notdir $@)"
	@$(CC) $(LDFLAGS) $(OBJDIR)/client.o $(LIBDIR)/$(TARGET).a -o $(BINDIR)/$@ $(LIB_PATH) $(LIBS)

clean:
	@rm -fr $(BUILD_DIR)
	@rm -fr *.cloak.c
	@rm -fr sib
	@rm -fr report*

-include $(DEPS)
