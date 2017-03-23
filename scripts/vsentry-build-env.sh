#!/bin/bash

sudo apt-get install libncurses-dev -y
sudo apt-get install pv -y

script_dir=`cd $(dirname $0); pwd`
kernel_dir=$script_dir/../..

cd ../../

for app in agl-3.0.2 ; do

	if [ ! -d "linux-yocto-4.4" ]; then

		git clone git@github.com:saferide-tech/linux-yocto-4.4.git

	else
		echo -n "linux-yocto-4.4 kernel source already exist... " 
		echo -e "" 
	fi

	if [ ! -e "$app.tar.gz" ] && [ ! -e "yocto-kernel-cache.tar.gz" ]; then 

		wget http://169.50.35.130:80/yocto-kernel-cache.tar.gz
		wget http://169.50.35.130:80/$app.tar.gz
		pv agl-3.0.2.tar.gz | tar -xzmp
		pv yocto-kernel-cache.tar.gz | tar -xzmp

	else

		echo -n "the tarballs already exist... " 
		echo -e ""

		while true; do
			read -p "Do you wish to extract them?" yn
			case $yn in
				[Yy]* ) 
					if [ ! -d "agl-3.0.2" ] && [ ! -d "yocto-kernel-cache" ] ; then
					#fix local kernel path

						pv agl-3.0.2.tar.gz | tar -xzmp
						pv yocto-kernel-cache.tar.gz | tar -xzmp

					else
						echo -n "the directories already exist... " 
						echo -e "" 
						while true; do
							read -p "Do you wish to overwrite??" yn
							case $yn in
								[Yy]* )
 									rm -rf agl-3.0.2/ yocto-kernel-cache/
									pv agl-3.0.2.tar.gz | tar -xzmp
									pv yocto-kernel-cache.tar.gz | tar -xzmp
						
									break;;
								[Nn]* ) break;;
								* ) echo "Answer yes or no.";;
							esac
						done
						
					fi					

					break;;
				[Nn]* ) break;;
				* ) echo "Answer yes or no.";;
			esac
		done
	

	fi

sed -i 's|'PATH-NAME'|'${kernel_dir}'|g' $script_dir/../../agl-3.0.2/poky/meta/recipes-kernel/linux/linux-yocto_4.4.bb

echo $PWD

ln -s src/vsentry-mod agl-3.0.2/poky/meta/recipes-kernel/vsentry-mod
ln -s src/vsentry-userspace agl-3.0.2/poky/meta/recipes-kernel/vsentry-userspace
ln -s src/vsentry-cpu agl-3.0.2/poky/meta/recipes-kernel/vsentry-cpu
ln -s src/vsentry-netdump agl-3.0.2/poky/meta/recipes-kernel/vsentry-netdump

done 

exit 0

#echo -n "Enter the domain for apache: "
#read domain

