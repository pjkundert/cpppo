#!/bin/bash -eux

apt-get -y update
apt-get -y install golang aufs-tools libdevmapper-dev

# get rid of interactive prompt
echo 'lxc lxc/directory string /var/lib/lxc' > /tmp/lxc_debconf
sudo debconf-set-selections -v /tmp/lxc_debconf
apt-get -y install lxc
rm -f /tmp/lxc_debconf

export GOPATH=~/usr/lib/go
export PATH=$GOPATH/bin:$PATH

mkdir -p "$GOPATH"

#GO GET docker...
go get -v github.com/dotcloud/docker
#rm -rf $GOPATH/src/github.com/dotcloud/docker/vendor/src/code.google.com/p/go.net/ipv6

#GO INSTALL...
go install -v github.com/dotcloud/docker/

#Mounting...
echo 'none /sys/fs/cgroup cgroup defaults 0 0' | sudo tee -a /etc/fstab
sudo mount /sys/fs/cgroup

#Properly installing docker from binaries...
wget https://get.docker.io/builds/Linux/x86_64/docker-latest -O /usr/local/bin/docker
chmod +x /usr/local/bin/docker

#RUN...
#docker run -i -t ubuntu /bin/bash