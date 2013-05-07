#
# GNU 'make' file
# 

# PY[23] is the target Python interpreter.  It must have pytest installed.

PY2=python
PY3=python3

# PY[23]TEST is the desired method of invoking py.test; either as a command, or
# loading it as module, by directly invoking the target Python interpreter.
PY2TEST=PYTHONPATH=/usr/local/lib/python2.7/site-packages $(PY2) -m pytest
PY3TEST=$(PY3) -m pytest

.PHONY: all test
all:

# Only run tests in this directory.
test:
	$(PY2TEST)
	$(PY3TEST)

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
