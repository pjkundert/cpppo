#
# GNU 'make' file
# 

# PY[3] is the target Python interpreter.  It must have pytest installed.
SHELL		= /bin/bash

PY		?= python
PY2		?= python2
PY2_V		= $(shell $(PY2) -c "import sys; print('-'.join((next(iter(filter(None,sys.executable.split('/')))),sys.platform,sys.subversion[0].lower(),''.join(map(str,sys.version_info[:2])))))"  )
PY3		?= python3
PY3_V		= $(shell $(PY3) -c "import sys; print('-'.join((next(iter(filter(None,sys.executable.split('/')))),sys.platform,sys.implementation.cache_tag)))" 2>/dev/null )


VERSION		= $(shell $(PY3) -c 'exec(open("version.py").read()); print( __version__ )')
WHEEL		= dist/cpppo-$(VERSION)-py3-none-any.whl

# TARGET=... nix-shell  # CPython version targets: py27, py3{10,11,12,13}
# (py27 requires reverting to an older nixpkgs.nix)
#TARGET		?= py312
export TARGET

NIX_OPTS	?= # --pure



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

# Some tests assume the local time-zone is:
TZ=Canada/Mountain


GIT_SSH_COMMAND	= ssh -o StrictHostKeyChecking=no
export GIT_SSH_COMMAND

GHUB_NAME	= cpppo
GHUB_REPO	= git@github.com:pjkundert/$(GHUB_NAME).git
GHUB_BRCH	= $(shell git rev-parse --abbrev-ref HEAD )

# We'll agonizingly find the directory above this makefile's path
VENV_DIR	= $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/.. )
VENV_NAME	= $(GHUB_NAME)-$(VERSION)-$(PY3_V)
VENV		= $(VENV_DIR)/$(VENV_NAME)
VENV_OPTS	=

# To see all pytest output, uncomment --capture=no
PYTESTOPTS=-v --capture=no --log-cli-level=WARNING # INFO 25 == NORMAL 23 == DETAIL

PY_TEST=TZ=$(TZ) $(PY)  -m pytest $(PYTESTOPTS)
PY2TEST=TZ=$(TZ) $(PY2) -m pytest $(PYTESTOPTS)
PY3TEST=TZ=$(TZ) $(PY3) -m pytest $(PYTESTOPTS)

.PHONY: all test clean FORCE
all:			help

help:
	@echo "GNUmakefile for cpppo.  Targets:"
	@echo "  help			This help"
	@echo "  test			Run unit tests under Python2/3 (no serial_test w/o 'make SERIAL_TEST=1 test')"
	@echo "  install		Install in /usr/local for Python2/3"
	@echo "  clean			Remove build artifacts"
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

analyze:
	$(PY3) -m flake8 --color never -j 1 --max-line-length=250 \
	  --exclude lib,bin,dist,build,signals,.git \
	  --ignore=W503,E201,E202,E203,E127,E211,E221,E222,E223,E225,E226,E231,E241,E242,E251,E265,E272,E274,E291 \

pylint:
	pylint . --disable=W,C,R

#
# nix-...:
#
# Use a NixOS environment to execute the make target, eg.
#
#     nix-venv-activate
#
#     The default is the Python 3 crypto_licensing target in default.nix; choose
# TARGET=py27 to test under Python 2 (more difficult as time goes on).  See default.nix for
# other Python version targets.
#
nix-%:
	nix-shell $(NIX_OPTS) --run "make $*"


#
# test...:	Perform Unit Tests
#
#     Assumes that the requirements.txt has been installed in the target Python environment.  This
# is probably best accomplished by first creating/activating a venv, and then running the test:
#
#     $ make nix-venv-activate
#     (crypto-licensing-4.0.0) [perry@Perrys-MBP crypto-licensing (feature-py-3.12)]$ make test
#     make[1]: Entering directory '/Users/perry/src/crypto-licensing'
#     ...
#
test:
	$(PY3TEST)

doctest:
	cd crypto/licensing && $(PY3TEST) --doctest-modules

analyze:
	flake8 -j 1 --max-line-length=110 \
	  --ignore=F401,E201,E202,E221,E223,E226,E231,E242,E272,E701,E702,W191,W291,W503,W293,W391,E \
	  --exclude="__init__.py" \
	  .

pylint:
	cd .. && pylint cpppo --disable=W,C,R


build-check:
	@$(PY3) -m build --version \
	    || ( echo "\n*** Missing Python modules; run:\n\n        $(PY3) -m pip install --upgrade -r requirements-dev.txt\n" \
	        && false )

build:	build-check clean wheel

wheel:	$(WHEEL)

$(WHEEL):	FORCE
	$(PY3) -m pip install -r requirements-dev.txt
	$(PY3) -m build .
	@ls -last dist

install:	$(WHEEL) FORCE
	$(PY3) -m pip install --force-reinstall $<[all]

install-%:  # ...-dev, -tests
	$(PY3) -m pip install --upgrade -r requirements-$*.txt


clean:
	@rm -rf MANIFEST *.png build dist auto *.egg-info $(shell find . -name '*.pyc' -o -name '__pycache__' )


# Run only tests with a prefix containing the target string, eg test-blah
test-%:
	$(PY3TEST) *$*_test.py

unit-%:
	$(PY3TEST) -k $*

#
# venv:		Create a Virtual Env containing the installed repo
#
.PHONY: venv
venv:			$(VENV)
	@echo; echo "*** Activating $< VirtualEnv for Interactive $(SHELL)"
	@bash --init-file $</bin/activate -i

$(VENV):
	@echo; echo "*** Building $@ VirtualEnv..."
	@rm -rf $@ && $(PY3) -m venv $(VENV_OPTS) $@ \
	    && source $@/bin/activate \
	    && make install install-tests

#
# Target to allow the printing of 'make' variables, eg:
#
#     make print-CXXFLAGS
#
print-%:
	@echo $* = $($*)
	@echo $*\'s origin is $(origin $*)
