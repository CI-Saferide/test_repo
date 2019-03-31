# Top level makefile, the real shit is at src/Makefile

default: all

.DEFAULT:
	cd src && $(MAKE) $@

install:
	cd src && $(MAKE) $@
	cp src/redis-server /usr/bin/redis-server

.PHONY: install
