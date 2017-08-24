CONFD_DIR = /var/vsentry/confd
CONFD = $(CONFD_DIR)/bin/confd
CONFD_INSTALL_BIN = ./confd-basic-6.4.linux.x86_64.installer.bin
CONFDC = $(CONFD_DIR)/bin/confdc
CONFD_FLAGS = --addloadpath $(CONFD_DIR)/etc/confd
CDB_DIR = $(CONFD_DIR)/confd-cdb

all: include/saferide.h saferide.fxs $(CONFD_DIR) $(CDB_DIR)

confd: $(CONFD)

include/saferide.h: saferide.h
	cp  $< $@

%.h: %.fxs
	$(CONFDC) --emit-h $*.h $*.fxs

%.fxs: %.yang
	$(CONFDC) $(FXS_WERR) $(EXTRA_LINK_FLAGS) -c -o $@  $<

start: stop
	$(CONFD) -c ./confd.conf $(CONFD_FLAGS)

stop:
	$(CONFD) --stop    || true

cli:
	$(CONFD_DIR)/bin/confd_cli --user=admin --groups=admin \
		--interactive || echo Exit

cleanall: clean cleandb

clean:
	rm include/saferide.h saferide.fxs

cleandb:
	rm -rf $(CDB_DIR)


$(CONFD): $(CONFD_DIR) $(CONFD_INSTALL_BIN)
	echo $?
	$(CONFD_INSTALL_BIN) $(CONFD_DIR)
	touch $@

$(CONFD_DIR):
	sudo mkdir -p $@
	sudo chown 1000:1000 $@ 
	sudo chmod 777 $@ 

$(CDB_DIR):
	-mkdir -p $(CDB_DIR)
	cp $(CONFD_DIR)/var/confd/cdb/aaa_init.xml $(CDB_DIR)
