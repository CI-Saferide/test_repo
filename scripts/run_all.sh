#!/bin/sh

cd vsentry-mod
./init_vsentry.sh
cd ..
cd confd
make start
cd ..
sudo ./vsentry-engine/build/bin/sr_engine
