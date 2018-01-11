#!/bin/bash
TOPDIR=$PWD
REDBLACK=1
YANG=1
PROTOBUF=1
PROTOBUF_C=1
SYSREPO=1

sudo apt-get install -y git cmake build-essential libcurl4-openssl-dev libpcre3-dev libev-dev autoconf unzip libtool

if [ $REDBLACK == '1' ]
then
               git clone https://github.com/sysrepo/libredblack.git && \
               cd libredblack && \
               ./configure --prefix=/usr && \
               make && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi

if [ $YANG == '1' ]
then
               git clone https://github.com/CESNET/libyang.git && \
               cd libyang && git checkout v0.13-r2 && mkdir build && cd build && \
               cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" .. && \
               make && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi


if [ $PROTOBUF == '1' ]
then
               git clone https://github.com/google/protobuf.git && \
               cd protobuf && ./autogen.sh && ./configure && \
               make && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi

if [ $PROTOBUF_C == '1' ]
then
               git clone https://github.com/protobuf-c/protobuf-c.git && \
               cd protobuf-c && ./autogen.sh && ./configure --prefix=/usr && \
               make && \
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
               cmake -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_CPP_EXAMPLES:BOOL=FALSE -DCMAKE_BUILD_TYPE:String="Release" -DREPOSITORY_LOC:PATH=/etc/sysrepo .. && \
               make && \
               sudo make install && \
               sudo ldconfig && \
               cd $TOPDIR
fi

