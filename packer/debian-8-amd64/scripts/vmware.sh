#!/bin/bash -eux

echo "Installing VMware Tools"

apt-get -y install linux-headers-$(uname -r) build-essential perl

case "$PACKER_BUILDER_TYPE" in 

virtualbox-iso|virtualbox-ovf) 
    mkdir /tmp/vbox
    VER=$(cat /home/vagrant/.vbox_version)
    mount -o loop /home/vagrant/VBoxGuestAdditions_$VER.iso /tmp/vbox 
    sh /tmp/vbox/VBoxLinuxAdditions.run
    umount /tmp/vbox
    rmdir /tmp/vbox
    rm /home/vagrant/*.iso
    ;;

vmware-iso|vmware-ovf) 
    mkdir /tmp/vmfusion
    mkdir /tmp/vmfusion-archive
    mount -o loop /home/vagrant/linux.iso /tmp/vmfusion
    tar xzf /tmp/vmfusion/VMwareTools-*.tar.gz -C /tmp/vmfusion-archive
    # For kernel 3.12+, download kgid_t/kuid_t fixes
    if dpkg --compare-versions $(uname -r) '>=' '3.12'; then
        echo "Downloading 3.12+ version of VMware HGFS module..."
        wget http://box.hardconsulting.com/vmhgfs-3_12.tar -O /tmp/vmfusion-archive/vmware-tools-distrib/lib/modules/source/vmhgfs.tar
    fi
    /tmp/vmfusion-archive/vmware-tools-distrib/vmware-install.pl --default
    umount /tmp/vmfusion
    rm -rf  /tmp/vmfusion
    rm -rf  /tmp/vmfusion-archive
    rm /home/vagrant/*.iso
    ;;

*)
    echo "Unknown Packer Builder Type >>$PACKER_BUILDER_TYPE<< selected."
    echo "Known are virtualbox-iso|virtualbox-ovf|vmware-iso|vmware-ovf."
    ;;

esac
