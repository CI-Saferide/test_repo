ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET = sr-engine
obj   += $(TARGET) 
$(TARGET)-objs := $(ROOT_DIR)/src/main.o \

	SRC := $(shell pwd)

all: libsr_log.a
	@mkdir -p $(ROOT_DIR)/../build/bin/
	$(CC) src/main.c -static -L$(ROOT_DIR)/../build/lib/ -I$(ROOT_DIR)/../../vsentry-mod/files/tools/sr-log/include/ -lsr_log -o $(ROOT_DIR)/../build/bin/$(TARGET)

libsr_log.a:  
	$(MAKE) -C ../tools/sr-log all MAKEFLAGS=-I../tools/sr-log/include
	
clean:
	find ../ -name "*~" -type f -delete
	find ../ -name "*.o" -type f -delete
	rm -rf $(ROOT_DIR)/../build
	
