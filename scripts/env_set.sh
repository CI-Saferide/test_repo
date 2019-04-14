# Aruments : xcode - compile with code
rm -rf mutual-repo
git clone -n git@github.com:saferide-tech/mutual-repo.git --depth 1
cd mutual-repo 
git checkout HEAD client/ && git checkout HEAD include/ && git checkout HEAD Makefile
if [[ $1 == "xcode" ]]; then
	XCODE="XCODE=1"
fi
make libclient $XCODE
HDIR=/usr/include/mutual_repo
if [[ ! -e $HDIR ]]; then
  sudo mkdir $HDIR
fi
sudo cp client/vproxy_client.h $HDIR
sudo cp include/message.h $HDIR
sudo cp client/build/lib/libclient.a /usr/lib
cd ..
rm -rf mutual-repo
