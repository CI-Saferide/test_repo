#!/bin/bash
TOPDIR=$PWD/tmp
REDBLACK=1
YANG=1
PROTOBUF=1
PROTOBUF_C=1

#set colors
export red='\e[0;31m'
export green='\e[0;32m'
export yellow='\e[1;33m'
export white='\e[1;37m'
export blue='\e[1;34m'
export nc='\e[0m'

check_status(){
	if [ $? != 0 ]; then 	
		echo -e "[ ${red} FAIL ${nc} ]"
		exit 1
	fi
}

TARGET=$1
if [ -z "${TARGET}" ]; then
    TARGET="/usr"
fi
#TARGET=$TOPDIR/saferide/

sudo apt-get install -y git cmake build-essential libpcre3-dev libev-dev autoconf unzip libtool curl libcurl4-openssl-dev libarchive-dev libssl-dev git

rm -rf $TOPDIR 2> /dev/null
mkdir -p $TOPDIR
mkdir -p $TARGET

if [ $YANG == '1' ]
then
               cd $TOPDIR
               git clone https://github.com/CESNET/libyang.git
               cd libyang && git checkout v0.13-r2 && mkdir build && cd build
               cmake -DCMAKE_INSTALL_PREFIX=${TARGET} -DCMAKE_PREFIX_PATH=${TARGET} -DCMAKE_BUILD_TYPE:String="Release" ..
               make -j4
               check_status
               sudo make install
               check_status
               sudo ldconfig
               echo -e "[  ${green} libyang OK ${nc}  ]"
fi


if [ $PROTOBUF == '1' ]
then
               cd $TOPDIR
               git clone https://github.com/google/protobuf.git
               cd protobuf && git checkout 3.5.1.1
               ./autogen.sh
               ./configure --prefix=${TARGET} LDFLAGS="-L${TARGET}"
               #./configure --prefix=/home/shay/git/vsentry/scripts/tmp/saferide LDFLAGS="-L/home/shay/git/vsentry/scripts/tmp/saferide"
               make -j4
               check_status
               sudo make install
               check_status
               sudo ldconfig
               echo -e "[  ${green} protobuf OK ${nc}  ]"
fi

if [ $PROTOBUF_C == '1' ]
then
               cd $TOPDIR
               git clone https://github.com/protobuf-c/protobuf-c.git
               cd protobuf-c && ./autogen.sh && export PKG_CONFIG_PATH=${TARGET}/lib/pkgconfig && ./configure --prefix=${TARGET}
               make -j4
               check_status
               sudo make install
               check_status
               sudo ldconfig
               echo -e "[  ${green} protobuf-c OK ${nc}  ]"
fi

#now lets make libsentry
cd $TOPDIR
git clone git@github.com:saferide-tech/open-sentry.git
cd open-sentry/libsentry/
make
sudo cp -rva build/lib/* ${TARGET}/lib/

#now install saferide.yang

#now let make update-manager
cd $TOPDIR
git clone git@github.com:saferide-tech/update-manager.git
cd update-manager
make
sudo cp -rva build/bin/* ${TARGET}/bin/

#remove static files, as we do not need them
cd $TARGET
sudo find -name "*.a" | sudo xargs rm
sudo rm -rf share/ man/ include/


