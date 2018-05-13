#!/bin/bash
TOPDIR=$PWD
REDBLACK=1
YANG=1
PROTOBUF=1
PROTOBUF_C=1
SYSREPO=1

TARGET=$1
if [ -z "${TARGET}" ]; then
    TARGET="/usr"
fi

sudo apt-get install -y git cmake build-essential libpcre3-dev libev-dev autoconf unzip libtool curl libcurl4-openssl-dev libarchive-dev libssl-dev git

if [ $REDBLACK == '1' ]
then
               git clone https://github.com/sysrepo/libredblack.git && \
               cd libredblack && \
               env LDFLAGS='-L${TARGET}' ./configure --prefix=${TARGET} && \
               make -j4 && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi

if [ $YANG == '1' ]
then
               git clone https://github.com/CESNET/libyang.git && \
               cd libyang && git checkout v0.13-r2 && mkdir build && cd build && \
               cmake -DCMAKE_INSTALL_PREFIX=${TARGET} -DCMAKE_PREFIX_PATH=${TARGET} -DCMAKE_BUILD_TYPE:String="Release" .. && \
               make -j4 && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi


if [ $PROTOBUF == '1' ]
then
               git clone https://github.com/google/protobuf.git && \
               cd protobuf && git checkout 3.5.1.1 && \
               ./autogen.sh && env LDFLAGS='-L${TARGET}' ./configure --prefix=${TARGET} && \
               make -j4 && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi

if [ $PROTOBUF_C == '1' ]
then
               git clone https://github.com/protobuf-c/protobuf-c.git && \
               cd protobuf-c && ./autogen.sh && export PKG_CONFIG_PATH=${TARGET}/lib/pkgconfig && ./configure --prefix=${TARGET} && \
               make -j4 && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi

if [ $SYSREPO == '1' ]
then
               git clone https://github.com/sysrepo/sysrepo.git && \
               cd sysrepo && \
               git checkout v0.7.0 && \
               mkdir build && cd build && \
               cmake -DCMAKE_INSTALL_PREFIX=${TARGET} -DCMAKE_PREFIX_PATH=${TARGET} -DBUILD_CPP_EXAMPLES:BOOL=FALSE -DCMAKE_BUILD_TYPE:String="Release" -DREPOSITORY_LOC:PATH=${TARGET}/sysrepo .. && \
               make -j4 && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi
