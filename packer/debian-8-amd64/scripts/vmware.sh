#!/bin/bash -eux

echo "Installing VMware Tools (vmhgfs) via open-vm-tools"


case "$PACKER_BUILDER_TYPE" in 
vmware-iso|vmware-ovf) 
    ;;
*)
    echo "Unknown Packer Builder Type >>$PACKER_BUILDER_TYPE<< selected."
    echo "Known are vmware-iso|vmware-ovf."
    ;;
esac

packages="open-vm-tools-dkms"

# If desired, set up "sid" in /etc/apt/{sources.list, preferences.d/sid_priority} This is sometimes
# necessary to get the latest version of some package (eg. to support building on latest kernel).
# vvvvvvvvvv Comment these lines in/out as required
packages="open-vm-tools-dkms/sid"

echo "deb http://http.us.debian.org/debian sid main" >> /etc/apt/sources.list
cat > /etc/apt/preferences.d/sid_priority <<EOF
Package: *
Pin: release a=testing
Pin-Priority: 700

Package: *
Pin: release a=unstable
Pin-Priority: 600
EOF
# ^^^^^^^^^^ Enable 'sid' in sources.list


apt-get -y update && apt-get -y install $packages

