#
# GNU 'make' file
# 

# PY is the target Python interpreter.  It must have pytest installed.  We''

# 
PYTHONPATH=/usr/local/lib/python2.7/site-packages
export PYTHONPATH
PY=python

#PY=python3

# PYTEST is the desired method of invoking py.test; either as a command, or
# loading it as module, by directly invoking the target Python interpreter.
PYTEST=py.test
PYTEST=$(PY) -m pytest
PYTEST=$(PY) -m pytest --capture=no

.PHONY: all test
all:

# Only run tests in this directory.
test:
	$(PYTEST)

# Run only tests with a prefix containing the target string, eg test-blah
test-%:
	$(PYTEST) *$*_test.py

unit-%:
	$(PYTEST) -k $*

#
# Target to allow the printing of 'make' variables, eg:
#
#     make print-CXXFLAGS
#
print-%:
	@echo $* = $($*)
	@echo $*\'s origin is $(origin $*)
