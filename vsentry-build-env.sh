#!/bin/bash

sudo apt-get install pv -y

echo -n "Enter the domain for apache: "
read domain

for app in agl-3.0 ; do

if [ ! -e "$app.tgz" ]; then
		wget http://169.50.35.130:80/$app.tgz
		pv ~/vsentry/$app.tgz | tar -xzmp

		cd $app/

		source meta-agl/scripts/aglsetup.sh -m qemux86-64 agl-demo agl-netboot agl-appfw-smack

		bitbake agl-demo-platform
else
    echo -n "the tarball $app already exists... " 
	echo -e "" 
fi

while true; do
    read -p "Do you wish to extract and build $app?" yn
    case $yn in
        [Yy]* ) 
			#tar -xmpf $app.tgz
			pv ~/git/$app.tgz | tar -xzmp

			cd $app/

			source meta-agl/scripts/aglsetup.sh -m qemux86-64 agl-demo agl-netboot agl-appfw-smack

			bitbake agl-demo-platform

			break;;
        [Nn]* ) exit;;
        * ) echo "Answer yes or no.";;
    esac
done

done


# add the vsentry src files:
# /home/saferide/AGL-blowfish204/poky/meta/recipes-kernel/
#add the lines in qemux86-64.conf file in:
#/home/saferide/AGL-blowfish204/poky/meta/conf/machine

#MACHINE_ESSENTIAL_EXTRA_RRECOMMENDS += "vsentry-mod"

#MACHINE_ESSENTIAL_EXTRA_RRECOMMENDS += "vsentry-userspace"

#MACHINE_ESSENTIAL_EXTRA_RRECOMMENDS += "vsentry-cpu"

#edit the linux-yocto.XX.bb
