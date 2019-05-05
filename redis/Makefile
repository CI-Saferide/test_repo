# Top level makefile, the real shit is at src/Makefile

default: all

.DEFAULT:
	cd deps && $(MAKE) hiredis
	cd deps && $(MAKE) linenoise
	cd src && $(MAKE) $@

.PHONY: install
