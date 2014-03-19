#
# GNU 'make' file -- packer.io images
# 
# 

SHELL=/bin/bash
PCKVER=0.5.2
PCKURI=https://dl.bintray.com/mitchellh/packer/$(PCKVER)_darwin_amd64.zip

.PHONY: all test clean
all:			help

help:
	@echo "GNUmakefile for cpppo Vagrant boxes using packer.io.  Targets:"
	@echo "  all                   This help (default)"
	@echo "  jessie64              Build jessie64 (Debian 8) Vagrant box image (vmware)"
	@echo "  add-jessie64          Add jessie64 Vagrant box image for ../vagrant/debian"
	@echo "  upload-jessie64       Upload new master jessie64 Vagrant box image to box.hardconsulting.com"
	@echo
	@echo "  packer                Install packer in /usr/local/bin/"
	@echo "  debian-8    |jessie64 Build debian 8 Jessie image"
	@echo "  debian-7.4.0|wheezy64 Build debian 7 Wheezy image"
	@echo "  clean                 Remove all generated box image build artifacts"
	@echo "  help                  This help"

clean:
	@find . \( -name 'packer_cache'					\
	       -o -name 'output-vmware-iso'				\
	       -o -name '*_vmware.box' \)				\
	    -exec rm -rf {} \; -print

debian-%:	debian-%-amd64 /usr/local/bin/packer
	@if [ ! -r $</$<_vmware.box ]; then				\
	    echo "Building $< box image";				\
	    cd $<;							\
	    if packer build -only vmware-iso $<.json; then		\
		echo "Building $<_vmware.box complete";			\
	    else							\
		echo "Building $< box image failed";			\
		exit 1;							\
	    fi;								\
	fi
	@ls -l $$(PWD)/$</$<_vmware.box

debian-8-amd64/debian-8-amd64_vmware.box:		debian-8
debian-7.4.0-amd64/debian-7.4.0-amd64_vmware.box:	debian-7.4.0

# Map the Debian nicknames to the packer.io outputs.  We need to identify the boxes according to the
# Vagrant --provider ... name (eg. vmware_destop vs. vmware).
wheezy64:	debian-7.4.0-amd64/debian-7.4.0-amd64_vmware.box
	ln -f $< $@-vmware_desktop.box

jessie64:	debian-8-amd64/debian-8-amd64_vmware.box
	ln -f $< $@-vmware_desktop.box

upload-%:	%
	rsync -zva --progress --inplace $<-vmware.box perry@box.hardconsulting.com:box/$<-vmware_desktop.box

add-%:		%
	cd ../vagrant/debian; vagrant box add $< $(PWD)/$<-vmware_desktop.box --provider vmware_desktop --force

/usr/local/bin/packer:
	@echo "Installing packer.io at $@"
	@cd $(dir $<);							\
	wget -c --progress=bar -O packer.zip $(PCKURI);			\
	touch packer.zip						\
	unzip packer.zip

FORCE:
