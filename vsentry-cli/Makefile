ifdef CROSS_COMPILE
export CC=$(CROSS_COMPILE)gcc
endif

CPPFLAGS += -I../common/include -I../vsentry-lib/include -I../vsentry-engine/sal/platform/linux/include -I../vsentry-engine/include -I../tools/sr-log/include -I../tools/db_tools/include -I../tools/redis_mng/include

TOP_DIR		:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR		:= $(BUILD_DIR)/objs
LIBDIR		:= $(BUILD_DIR)/lib
BINDIR 		:= $(BUILD_DIR)/bin

TARGET 		:= vsentry_cli

# where to search for sources
VPATH 		:=  $(TOP_DIR)/src \

# sources to compile
SRCS 		:=  vsentry_cli.c \

# include folders
INCLUDES 	:=

OBJS		:=  $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:=  $(OBJS:.o=.d)

# libs to link with
LIBS		:= -l$(TARGET) -lsentry -lredis_mng -ldb_tools
# and where to search them 
LIB_PATH 	:= -L$(LIBDIR) -L$(TOP_DIR)/../vsentry-engine/build/lib

CFLAGS 		+= -MMD -Wall

ifdef DEBUG
CFLAGS		+= -g -O0 -DDEBUG
else
CFLAGS 		+= -O2
endif

all: $(TARGET)

$(TARGET): lib$(TARGET) libdb_tools libredis_mng
	@echo "linking $(notdir $@)"
	$(CC) $(LDFLAGS) -o $(BINDIR)/$(TARGET) $(LIB_PATH) $(LIBS)

lib$(TARGET): OBJSDIR $(OBJS)
	@echo "archiving $(notdir $@)"
	@$(AR) rc $(LIBDIR)/$@.a $(OBJS)

OBJSDIR:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)
	@mkdir -p $(BINDIR)

libdb_tools:
	@$(MAKE) -s -C ../tools/db_tools TOP_DIR=$(TOP_DIR)

libredis_mng:
	@$(MAKE) -s -C ../tools/redis_mng TOP_DIR=$(TOP_DIR)


$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	$(CC) $(CPPFLAGS) -g $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

install:
	install -m 755 build/bin/* /usr/bin/

-include $(DEPS)



