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
	@echo "  all                     This help (default)"
	@echo "  vmware-jessie64         Build jessie64 (Debian 8) Vagrant box image (vmware)"
	@echo "  virtualbox-jessie64     Build jessie64 (Debian 8) Vagrant box image (virtualbox)"
	@echo "  add-vmware-jessie64     Add jessie64 Vagrant vmware box image to the ../vagrant/debian Vagrantfile installation (builds if necessary)"
	@echo "  clean                   Remove all generated box image build artifacts"
	@echo "  dist-clean              Remove downloaded ISOs and generated build artifacts"
	@echo 
	@echo "  upload-vmware-jessie64  Upload new master jessie64 vmware Vagrant box image to box.hardconsulting.com (if you have permissions)"
	@echo "  help                    This help"
	@echo
	@echo "Supported Debian version:"
	@echo "  jessie64 (Debian 8 testing) "
	@echo "  wheezy64 (Debian 7 stable) "
clean:		FORCE
	@find . \( -name 'output-vmware-iso' -o -name '*.box' \)	\
	    -exec rm -rf {} \; -print
dist-clean:	clean FORCE
	@find . \( -name 'packer_cache' \)				\
	    -exec rm -rf {} \; -print

# Validate all known Vagrant box nicknames
jessie64 wheezy64:
	@echo "Building Debian $@ VM image"

# Validate all known Vagrant box types
virtualbox vmware:
	@echo "Building Vagrant $@ VM box"

# Map the Debian architecture-specific nickname box images to the raw Vagrant box images.  The
# nicknamed vmware images must be named after the specific Vagrant --provider, not the generic VM
# name (eg. vmware_desktop instead of vmware)
%-jessie64:	% jessie64 debian-8-amd64/debian-8-amd64_%.box
	@ln -f $(lastword $^) jessie64-$(patsubst vmware,vmware_desktop,$<).box
	@shasum $(CURDIR)/jessie64-$(patsubst vmware,vmware_desktop,$<).box
%-wheezy64:	% wheezy64 debian-7.4.0-amd64/debian-7.4.0-amd64_%.box
	@ln -f $(lastword $^) wheezy64-$(patsubst vmware,vmware_desktop,$<).box
	@shasum $(CURDIR)/wheezy64-$(patsubst vmware,vmware_desktop,$<).box

# Map the known raw Vagrant box images to Packer.io build targets.
debian-8-amd64/debian-8-amd64_vmware.box:		debian-8-amd64-vmware
debian-8-amd64/debian-8-amd64_virtualbox.box:		debian-8-amd64-virtualbox
debian-7.4.0-amd64/debian-7.4.0-amd64_vmware.box:	debian-7.4.0-amd64-vmware
debian-7.4.0-amd64/debian-7.4.0-amd64_virtualbox.box:	debian-7.4.0-amd64-virtualbox

# Packer.io build targets; build if missing.  % directories (eg. ./debian-8-amd64/) must exist.
%-vmware %-virtualbox:	% /usr/local/bin/packer FORCE
	@echo "Building $</$<_$(patsubst $<-%,%,$@).box"
	@[ -r $</$<_$(patsubst $<-%,%,$@).box ] || ( cd $< && packer build -only $(patsubst $<-%,%-iso,$@) $<.json );
	@shasum $(CURDIR)/$</$<_$(patsubst $<-%,%,$@).box

# Build (if necessary) and add or upload the target (eg. jessie64-vmware) Vagrant box image.  Must
# use the Vagrant --provider name for the box image.
add-vmware-%:		% vmware-%
	cd ../vagrant/debian; vagrant box add $< $(CURDIR)/$<-vmware_desktop.box --provider vmware_desktop --force
add-virtualbox-%:	% virtualbox-%
	cd ../vagrant/debian; vagrant box add $< $(CURDIR)/$<-virtualbox.box --provider virtualbox --force
upload-vmware-%:	% vmware-%
	rsync -zva --progress --inplace $<-vmware_desktop.box perry@box.hardconsulting.com:box/
upload-virtualbox-%:	% virtualbox-%
	rsync -zva --progress --inplace $<-virtualbox.box perry@box.hardconsulting.com:box/

/usr/local/bin/packer:
	@echo "Installing packer.io at $@"
	@cd $(dir $<);							\
	wget -c --progress=bar -O packer.zip $(PCKURI);			\
	touch packer.zip						\
	unzip packer.zip

FORCE:
