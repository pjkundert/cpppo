#!/bin/bash -eux

# Clean up
apt-get -y remove linux-headers-$(uname -r) build-essential
apt-get -y autoremove
apt-get -y purge $(dpkg --list |grep '^rc' |awk '{print $2}')
apt-get -y purge $(dpkg --list |egrep 'linux-image-[0-9]' |awk '{print $3,$2}' |sort -nr |tail -n +2 |grep -v $(uname -r) |awk '{ print $2}')
apt-get -y clean

# Cleanup Virtualbox
rm -rf VBoxGuestAdditions_*.iso VBoxGuestAdditions_*.iso.?

# Cleanup Chef
rm -f /tmp/chef*deb

# Removing leftover leases and persistent rules
echo "cleaning up dhcp leases"
rm /var/lib/dhcp/*

# Make sure Udev doesn't block our network
mkdir /etc/udev/rules.d/70-persistent-net.rules
rm /lib/udev/rules.d/75-persistent-net-generator.rules
rm -rf /dev/.udev/ /var/lib/dhcp3/*
echo "pre-up sleep 2" >> /etc/network/interfaces

echo "Adding a 2 sec delay to the interface up, to make the dhclient happy"
echo "pre-up sleep 2" >> /etc/network/interfaces

# Zero out the free space to save space in the final image, blocking 'til
# written otherwise, the disk image won't be zeroed, and/or Packer will try to
# kill the box while the disk is still full and that's bad.
echo "Zeroing device to make space..."
dd if=/dev/zero of=/EMPTY bs=1M; sync
rm -f /EMPTY; sync
