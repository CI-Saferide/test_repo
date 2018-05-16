#!/bin/sh
curr_dir=`cd $(dirname $0); pwd`

module="vsentry"
device="vsentry"
mode="666"

sudo rm -f /dev/${device} 2> /dev/null || true
sudo rmmod $module.ko 2> /dev/null || true
sudo insmod $curr_dir/$module.ko $* || exit 1
major=`cat /proc/devices | awk "\\$2==\"$module\" {print \\$1}"`
sudo mknod /dev/${device} c $major 0
sudo chmod $mode /dev/${device}

