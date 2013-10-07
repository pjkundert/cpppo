#
# GNU 'make' file
# 

# PY[23] is the target Python interpreter.  It must have pytest installed.

PY2=python
PY3=python3

# PY[23]TEST is the desired method of invoking py.test; either as a command, or
# loading it as module, by directly invoking the target Python interpreter.
# 
# Ensure your locale is set to a UTF-8 encoding; run 'locale'; you should see something like:
 
#     LANG=en_CA.UTF-8
#     LANGUAGE=en_CA:en
#     LC_CTYPE="en_CA.UTF-8"
#     LC_NUMERIC="en_CA.UTF-8"
#     LC_TIME="en_CA.UTF-8"
#     LC_COLLATE="en_CA.UTF-8"
#     LC_MONETARY="en_CA.UTF-8"
#     LC_MESSAGES="en_CA.UTF-8"
#     LC_PAPER="en_CA.UTF-8"
#     LC_NAME="en_CA.UTF-8"
#     LC_ADDRESS="en_CA.UTF-8"
#     LC_TELEPHONE="en_CA.UTF-8"
#     LC_MEASUREMENT="en_CA.UTF-8"
#     LC_IDENTIFICATION="en_CA.UTF-8"
#     LC_ALL=en_CA.UTF-8
#     ...
# 
# Set in your .bashrc:
#     LANG=en_CA.UTF-8
#     LC_ALL=en_CA.UTF-8
# 
PYTESTOPTS=--capture=no
PY2TEST=$(PY2) -m pytest $(PYTESTOPTS)
PY3TEST=$(PY3) -m pytest $(PYTESTOPTS)

.PHONY: all test clean upload
all:			help

help:
	@echo "GNUmakefile for cpppo.  Targets:"
	@echo "  help		This help"
	@echo "  test		Run unit tests under Python2/3"
	@echo "  install	Install in /usr/local for Python2/3"
	@echo "  clean		Remove build artifacts"
	@echo "  upload		Upload new version to pypi (package maintainer only)"
	@echo "  virtualization	Install all potential Vagrant virtual machines"
	@echo
	@echo "    virtualbox-*	Manage VirtualBox    virtual machine"
	@echo "    vmware-*	Manage VMWare Fusion virtual machine (recommended; requires license)"
	@echo "       ...-up	  Bring up the virtual machine, configuring if necessary"
	@echo "       ...-halt	  Stop the virtual machine"
	@echo "       ...-destroy Discard the configured virtual machine"
	@echo
	@echo "       ...-ssh	  Establish SSH communications with the virtual machine"

test:
	$(PY2TEST)
	$(PY3TEST)

install:
	$(PY2) setup.py install
	$(PY3) setup.py install

# Support uploading a new version of cpppo to pypi.  Must:
#   o advance __version__ number in cpppo/misc.py
#   o log in to your pypi account (ie. for package maintainer only)
upload:
	python setup.py sdist upload

clean:
	rm -f MANIFEST *.png $(shell find . -name '*.pyc' )
	rm -rf build dist auto __pycache__ *.egg-info

# Virtualization management, eg:
#     make vmware-up/halt/ssh/destroy
# 
# To use a different Vagrant box than precise64 (eg. raring), Vagrantfile must be altered
.PHONY: virtualization vagrant vagrant_boxes				\
	precise64_virtualbox precise64_vmware_fusion			\
	raring_virtualbox

vmware-%:		precise64_vmware_fusion
	vagrant $* $(if $(filter up, $*), --provider=vmware_fusion,)

virtualbox-%:		precise64_virtualbox
	vagrant $* $(if $(filter up, $*), --provider=virtualbox,)

virtualization:	vagrant_boxes

vagrant:
	@vagrant --help >/dev/null || ( echo "Install vagrant: http://vagrantup.com"; exit 1 )

vagrant_boxes:		precise64_virtualbox				\
			precise64_vmware_fusion				\
			raring_virtualbox

raring_virtualbox:	$(HOME)/.vagrant.d/boxes/raring/virtualbox

precise64_virtualbox:	$(HOME)/.vagrant.d/boxes/precise64/virtualbox

precise64_vmware_fusion:$(HOME)/.vagrant.d/boxes/precise64/vmware_fusion

$(HOME)/.vagrant.d/boxes/raring/virtualbox:		vagrant
	@if [ ! -d $@ ]; then 						\
	    vagrant box add raring http://cloud-images.ubuntu.com/raring/current/raring-server-cloudimg-vagrant-amd64-disk1.box; \
	fi

$(HOME)/.vagrant.d/boxes/precise64/virtualbox:		vagrant
	@if [ ! -d $@ ]; then 						\
	    vagrant box add precise64 http://files.vagrantup.com/precise64.box;	\
	fi

$(HOME)/.vagrant.d/boxes/precise64/vmware_fusion: 	vagrant
	@if [ ! -d $@ ]; then						\
	    vagrant box add precise64 http://files.vagrantup.com/precise64_vmware_fusion.box; \
	fi


# Run only tests with a prefix containing the target string, eg test-blah
test-%:
	$(PY2TEST) *$*_test.py
	$(PY3TEST) *$*_test.py

unit-%:
	$(PY2TEST) -k $*
	$(PY3TEST) -k $*


#
# Target to allow the printing of 'make' variables, eg:
#
#     make print-CXXFLAGS
#
print-%:
	@echo $* = $($*)
	@echo $*\'s origin is $(origin $*)
