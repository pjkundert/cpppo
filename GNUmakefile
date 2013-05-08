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
PY2TEST=PYTHONPATH=/usr/local/lib/python2.7/site-packages $(PY2) -m pytest
PY2TEST=$(PY2) -m pytest
PY3TEST=PYTHONIOENCODING=UTF-8 $(PY3) -m pytest # --capture=no
PY3TEST=$(PY3) -m pytest # --capture=no

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
