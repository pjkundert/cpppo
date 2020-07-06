#
# GNU 'make' file
# 

# PY[3] is the target Python interpreter.  It must have pytest installed.

PY=python
PY2=python2
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

# To see all pytest output, uncomment --capture=no
PYTESTOPTS=-v # --capture=no

PY_TEST=TZ=$(TZ) $(PY)  -m pytest $(PYTESTOPTS)
PY2TEST=TZ=$(TZ) $(PY2) -m pytest $(PYTESTOPTS)
PY3TEST=TZ=$(TZ) $(PY3) -m pytest $(PYTESTOPTS)

.PHONY: all test clean upload
all:			help

help:
	@echo "GNUmakefile for cpppo.  Targets:"
	@echo "  help			This help"
	@echo "  test			Run unit tests under Python2/3 (no serial_test w/o 'make SERIAL_TEST=1 test')"
	@echo "  install		Install in /usr/local for Python2/3"
	@echo "  clean			Remove build artifacts"
	@echo "  upload			Upload new version to pypi (package maintainer only)"
	@echo
	@echo "    virtualbox-*		Manage VirtualBox    virtual machine"
	@echo "    vmware-*		Manage VMWare Fusion virtual machine (recommended; requires license)"
	@echo "      -debian-...	Specify Debian Jessie  64-bit VM (VMware 6 compatible)"
	@echo "      -ubuntu-...	Specify Ubuntu Precise 64-bit VM (VMware 5 compatible)"
	@echo "       ...-up		Bring up the virtual machine, configuring if necessary"
	@echo "       ...-halt		Stop the virtual machine"
	@echo "       ...-destroy	Discard the configured virtual machine"
	@echo
	@echo "       ...-ssh		Establish SSH communications with the virtual machine"
	@echo 
	@echo "EXAMPLES"
	@echo "  vmware-debian-up	Brings up Jessie VM w/ Docker capability" 
	@echo "  vmware-debian-ssh	Log in to the VM" 

test:
	$(PY_TEST)
test2:
	$(PY2TEST)
test3:
	$(PY3TEST)
test23:
	$(PY2TEST)
	$(PY3TEST)

install:
	$(PY) setup.py install
install2:
	$(PY2) setup.py install
install3:
	$(PY3) setup.py install
install23:
	$(PY2) setup.py install
	$(PY3) setup.py install

analyze:
	flake8 -j 1 --max-line-length=110					\
	  --ignore=F401,E221,E201,E202,E203,E223,E225,E226,E231,E241,E242,E261,E272,E302,W503,E701,E702,E,W	\
	  --exclude="__init__.py" \
	  .

pylint:
	cd .. && pylint cpppo --disable=W,C,R

# Support uploading a new version of cpppo to pypi.  Must:
#   o advance __version__ number in cpppo/version.py
#   o log in to your pypi account (ie. for package maintainer only)
upload:
	python setup.py sdist upload

clean:
	@rm -rf MANIFEST *.png build dist auto *.egg-info $(shell find . -name '*.pyc' -o -name '__pycache__' )

# Virtualization management, eg:
#     make {vmware,vagrant}-up/halt/ssh/destroy
# 
# To use a different Vagrant box than precise64 (eg. raring), Vagrantfile must be altered
.PHONY: vagrant vagrant_boxes						\
	precise64_virtualbox precise64_vmware_fusion			\
	raring_virtualbox

# The vagrant/ubuntu/Vagrantfile doesn't contain a config.vm.box_url; we must
# supply.  The precise64 VMware image presently supports only VMware Fusion 5;
# if you see an error regarding hgfs kernel modules, you may be running a
# version of VMware Fusion incompatible with the VMware Tools in the image.
# TODO: remove; no longer supported.
vmware-ubuntu-%:	precise64-vmware_fusion
	cd vagrant/ubuntu; vagrant $* $(if $(filter up, $*), --provider=vmware_fusion,)

virtualbox-ubuntu-%:	precise64-virtualbox
	cd vagrant/ubuntu; vagrant $* $(if $(filter up, $*), --provider=virtualbox,)

# The jessie64 VMware image is compatible with VMware Fusion 6, and the VirtualBox image is
# compatible with VirtualBox 4.3.  Obtains the box, if necessary.  The packer.io generated VMware
# boxes identify themselves as being for vmware_desktop; these are compatible with vmware_fusion
vmware-debian-%:	jessie64-vmware_desktop
	cd vagrant/debian; vagrant $* $(if $(filter up, $*), --provider=vmware_fusion,)

virtualbox-debian-%:	jessie64-virtualbox
	cd vagrant/debian; vagrant $* $(if $(filter up, $*), --provider=virtualbox,)

vagrant:
	@vagrant --help >/dev/null || ( echo "Install vagrant: http://vagrantup.com"; exit 1 )


# Check if jessie64-{virtualbox,vmware_desktop} exists in the vagrant box list.
# If not, install it.
jessie64-%:
	@if ! vagrant box list | grep -q '^jessie64.*($*'; then		\
	    vagrant box add jessie64 http://box.hardconsulting.com/jessie64-$*.box --provider $*; \
	fi



# Run only tests with a prefix containing the target string, eg test-blah
test-%:
	$(PY_TEST) *$*_test.py
test2-%:
	$(PY2TEST) *$*_test.py
test3-%:
	$(PY3TEST) *$*_test.py
test23-%:
	$(PY2TEST) *$*_test.py
	$(PY3TEST) *$*_test.py

unit-%:
	$(PY_TEST) -k $*
unit2-%:
	$(PY2TEST) -k $*
unit3-%:
	$(PY3TEST) -k $*
unit23-%:
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
