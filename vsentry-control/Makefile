ifdef CROSS_COMPILE
export CC=$(CROSS_COMPILE)gcc
endif


TOP_DIR		:= $(shell pwd)
BUILD_DIR 	:= $(TOP_DIR)/build
OBJDIR		:= $(BUILD_DIR)/objs
LIBDIR		:= $(BUILD_DIR)/lib
BINDIR 		:= $(BUILD_DIR)/bin

TARGET 		:= vsentry_ctrl

# where to search for sources
VPATH 		:=  $(TOP_DIR)/src \

# sources to compile
SRCS 		:=  control_cmd.c \

# include folders
INCLUDES 	:=

OBJS		:=  $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DEPS		:=  $(OBJS:.o=.d)

# libs to link with
LIBS		:= -l$(TARGET)
# and where to search them 
LIB_PATH 	:= -L$(LIBDIR)

CFLAGS 		+= -MMD -Wall

ifdef DEBUG
CFLAGS		+= -g -O0
else
CFLAGS 		+= -O2
endif

all: $(TARGET)

$(TARGET): lib$(TARGET)
	@echo "linking $(notdir $@)"
	@$(CC) $(LDFLAGS) -o $(BINDIR)/$(TARGET) $(LIB_PATH) $(LIBS)

lib$(TARGET): OBJSDIR $(OBJS)
	@echo "archiving $(notdir $@)"
	@$(AR) rc $(LIBDIR)/$@.a $(OBJS)

OBJSDIR:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)
	@mkdir -p $(BINDIR)

$(OBJDIR)/%.o: %.c
	@echo "compiling $(notdir $<)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@rm -fr $(BUILD_DIR)

-include $(DEPS)


