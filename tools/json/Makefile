BUILD_DIR       := $(TOP_DIR)/build
OBJDIR          := $(BUILD_DIR)/objs
LIBDIR          := $(BUILD_DIR)/lib

#CFLAGS += -g

all: $(LIBDIR)/libjsmn.a 

$(LIBDIR)/libjsmn.a: $(OBJDIR)/jsmn.o
	$(AR) rc $@ $^

$(OBJDIR)/%.o: %.c jsmn.h
	$(CC) -c $(CFLAGS) $< -o $@

test: test_default test_strict test_links test_strict_links
test_default: test/tests.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o test/$@
	./test/$@
test_strict: test/tests.c
	$(CC) -DJSMN_STRICT=1 $(CFLAGS) $(LDFLAGS) $< -o test/$@
	./test/$@
test_links: test/tests.c
	$(CC) -DJSMN_PARENT_LINKS=1 $(CFLAGS) $(LDFLAGS) $< -o test/$@
	./test/$@
test_strict_links: test/tests.c
	$(CC) -DJSMN_STRICT=1 -DJSMN_PARENT_LINKS=1 $(CFLAGS) $(LDFLAGS) $< -o test/$@
	./test/$@

clean:
	rm -f $(OBJDIR)/jsmn.o
	rm -f $(LIBDIR)/libjsmn.a

.PHONY: all clean test

