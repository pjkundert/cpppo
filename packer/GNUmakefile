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
	@echo "  all            This help (default)"
	@echo "  debian         Build debian 8 Jessie image"
	@echo
	@echo "  packer         Install packer in /usr/local/bin/"
	@echo "  debian-8       Build debian 8 Jessie image"
	@echo "  debian-7.4.0   Build debian 7 Wheezy image"
	@echo "  clean          Remove all generated box image build artifacts"
	@echo "  help           This help"

clean:
	@find . \( -name 'packer_cache'					\
	       -o -name 'output-vmware-iso'				\
	       -o -name '*_vmware.box' \)				\
	    -exec rm -rf {} \; -print

debian:		debian-8

debian-%:	debian-%-amd64 /usr/local/bin/packer
	@if [ ! -r $<_vmware.box ]; then				\
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

/usr/local/bin/packer:
	@echo "Installing packer.io at $@"
	@cd $(dir $<);							\
	wget -c --progress=bar -O packer.zip $(PCKURI);			\
	touch packer.zip						\
	unzip packer.zip

FORCE:
