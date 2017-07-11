#!/bin/sh
module="vsentry"
device="vsentry"
mode="666"

rm -f /dev/${device}
sudo rmmod $module.ko
sudo insmod $module.ko $* || exit 1
major=`cat /proc/devices | awk "\\$2==\"$module\" {print \\$1}"`
mknod /dev/${device} c $major 0
chmod $mode /dev/${device}

