#!/bin/bash

script_dir=`cd $(dirname $0); pwd`
build_dir=$script_dir/../kernel-mod/files/tools

cd $build_dir/sr-log

#echo $build_dir/vs-log
echo -n "***vSentry build tool***"
echo -e ""

while true; do
	read -p "yes for building no for cleaning:" yn
		case $yn in
			[Yy]* )
				make clean
				make
				gcc main.c -static -L/$build_dir/sr-log -lsr_log -o main
					while true; do
						read -p "Do you wish to run the program?" yn
							case $yn in
								[Yy]* )
									./main
									break;;
								[Nn]* ) break;;
								* ) echo "Answer yes or no.";;
							esac
					done
				break;;
			[Nn]* ) 
				make clean
				break;;
			* ) echo "Answer yes or no.";;
		esac
done


#gcc ../../files/src/main.c -static -L.  -lsr_log -o ../../tools/sr-log/main

