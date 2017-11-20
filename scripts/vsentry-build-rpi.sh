#!/bin/bash
sudo apt-get install -y bc build-essential gcc-aarch64-linux-gnu git gcc-arm-linux-gnueabi gcc-arm-linux-gnueabihf libncurses-dev pv unzip

script_dir=`cd $(dirname $0); pwd`
kernel_dir=$script_dir/../..
KERNEL=kernel7

cd ../../

while true; do
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e "" 
	lsblk
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e "" 
	echo -n "Check your lsblk first!!! if your SD card is not on sdb stop the script now!!!"
	echo -e ""
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e ""	
	read -p "Do you wish to create the bootable SD card for rpi?" yn
	case $yn in
		[Yy]* )
			pv -tpreb raspbian-jessie.img |sudo dd of=/dev/sdb bs=4M				
			break;;
		[Nn]* ) break;;
		* ) echo "Answer yes or no.";;
	esac
done

if [ ! -d "linux-rpi" ]; then

	#To get the sources, refer to the original GitHub repository for the various branches
	git clone https://github.com/saferide-tech/linux-rpi.git

else
	echo -n "linux-rpi kernel source already exist... " 
	echo -e "" 
fi

cd linux-rpi/

while true; do
	read -p "Do you wish compile the rpi kernel? " yn
	case $yn in
		[Yy]* )
			make ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- bcm2709_defconfig
			make ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- zImage modules dtbs -j8
#			make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- bcmrpi3_defconfig
#			make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j 8					
			break;;
		[Nn]* ) break;;
		* ) echo "Answer yes or no.";;
	esac
done

echo -n "need to copy to raspberry pi SD card.." 
echo -e ""

while true; do
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e "" 
	lsblk
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e "" 
	echo -n "Check your lsblk first!!! if your SD card is not on sdb stop the script now!!!"
	echo -e ""
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e ""	 
	read -p "Do you wish to install VSENTRY on the SD card for rpi? " yn
	case $yn in
		[Yy]* )
			if [ ! -d "mnt" ]; then
				echo -n "Creating temp mnt dir..." 
				echo -e "" 
			else
				echo -n "mnt dir already exist...recreating " 
				echo -e "" 
				sudo umount /dev/sdb1 mnt/fat32
				sleep 2s
				sudo umount /dev/sdb2 mnt/ext4
				sleep 5s
				rm -rf mnt
			fi
			
			mkdir -p mnt/fat32
			mkdir -p mnt/ext4
			sleep 1s 
			sudo mount /dev/sdb1 mnt/fat32
			sleep 1s
			sudo mount /dev/sdb2 mnt/ext4
			sleep 1s
#			cp -R ../vsentry/ mnt/ext4/home/pi/vsentry/
			cd ../vsentry/vsentry-mod/
			echo $PWD
			make ARCH=arm KERNEL_SRC=~/git/linux-rpi CROSS_COMPILE=/usr/bin/arm-linux-gnueabi-
			echo $PWD
			cp vsentry.ko ../../linux-rpi/mnt/ext4/home/pi/
			cp init_vsentry.sh ../../linux-rpi/mnt/ext4/home/pi/
			sleep 1s
			#make clean
			cd ../vsentry-engine/
			echo $PWD
			make ARCH=arm KERNEL_SRC=~/git/linux-rpi CROSS_COMPILE=/usr/bin/arm-linux-gnueabi-
			echo $PWD
			cd build/bin/
			echo $PWD
			cp sr_engine ../../../../linux-rpi/mnt/ext4/home/pi/
			echo $PWD
			cd ../../	
			echo $PWD		
			make clean
			cd ../../linux-rpi/
			echo $PWD
			sleep 1s
			sudo umount mnt/fat32
			sleep 2s
			sudo umount mnt/ext4
			sleep 1s
			echo -n "removing temp mnt dir..." 
			echo -e ""
			rm -rf mnt					
			break;;
		[Nn]* ) break;;
		* ) echo "Answer yes or no.";;
	esac
done

while true; do
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e "" 
	lsblk
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e "" 
	echo -n "Check your lsblk first!!! if your SD card is not on sdb stop the script now!!!"
	echo -e ""
	echo -n "***WARNING***WARNING***WARNING***WARNING***WARNING***WARNING***"
	echo -e ""	 
	read -p "Do you wish to install modules on the SD card for rpi? " yn
	case $yn in
		[Yy]* )
			if [ ! -d "mnt" ]; then
				echo -n "Creating temp mnt dir..." 
				echo -e "" 
			else
				echo -n "mnt dir already exist...recreating " 
				echo -e "" 
				sudo umount /dev/sdb1 mnt/fat32
				sleep 2s
				sudo umount /dev/sdb2 mnt/ext4
				sleep 5s
				rm -rf mnt
			fi
			
			mkdir -p mnt/fat32
			mkdir -p mnt/ext4
			sleep 1s 
			sudo mount /dev/sdb1 mnt/fat32
			sleep 1s
			sudo mount /dev/sdb2 mnt/ext4
			sleep 1s
			sudo make ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnueabi- INSTALL_MOD_PATH=mnt/ext4 modules_install
#			sudo make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- INSTALL_MOD_PATH=mnt/ext4 modules_install
			sleep 1s
			sudo cp arch/arm/boot/zImage mnt/fat32/$KERNEL.img
			sudo cp arch/arm/boot/dts/*.dtb mnt/fat32/
			sudo cp arch/arm/boot/dts/overlays/*.dtb* mnt/fat32/overlays/
			sudo cp arch/arm/boot/dts/overlays/README mnt/fat32/overlays/
			echo $PWD
			sleep 1s
			sudo umount mnt/fat32
			sleep 2s
			sudo umount mnt/ext4
			sleep 1s
			echo -n "removing temp mnt dir..." 
			echo -e ""
			rm -rf mnt					
			break;;
		[Nn]* ) break;;
		* ) echo "Answer yes or no.";;
	esac
done


echo -n "You need to edit the config.txt file to select the kernel that the Pi will boot into:"
echo -e ""
echo -n "add the line kernel=kernel7.img in the config.txt"
echo -e ""
	


echo $PWD

exit 0

