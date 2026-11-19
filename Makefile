# GNU Make. See CLAUDE.md for the development and testing workflow.
SHELL := /bin/bash
.DEFAULT_GOAL := help

PYTHON ?= $(or $(PY3),$(CPPPO_PYTHON),$(if $(VIRTUAL_ENV),python,python3))
TARGET ?=
NIX_OPTS ?=
TZ := Canada/Mountain
PYTESTOPTS ?= -ra
TEST_ARGS ?=
DIST_DIR ?= dist

# Use a per-interpreter environment. Inside the flake, create it on demand
# unless the caller has already activated an environment in that shell.
VENV_DIR ?= $(CURDIR)/.venv
PYTHON_TAG = $(shell $(PYTHON) -c 'import platform, sys; print("-".join((platform.python_implementation().lower(), platform.python_version(), sys.platform)))')
VENV ?= $(VENV_DIR)/$(PYTHON_TAG)
VENV_OPTS ?=
USE_VENV ?= $(if $(VIRTUAL_ENV),,$(CPPPO_NIX_SHELL))
ifeq ($(USE_VENV),1)
RUN_PYTHON = "$(VENV)/bin/python"
TEST_ENV := venv-setup
else
RUN_PYTHON = $(PYTHON)
endif

.PHONY: help all test venv venv-setup install build build-check wheel clean analyze pylint
all: help

help:
	@printf '%s\n' 'Cpppo development targets (GNU Make)' \
	  '  make nix-test                       Run the suite on Nix CPython 3.13' \
	  '  make TARGET=py27 nix-test           Run the suite on Nix CPython 2.7' \
	  '  make TARGET=py312 nix-test-enip     Run matching *_test.py files' \
	  '  make nix-unit-client                Select tests by pytest keyword' \
	  '  make nix-test TEST_ARGS=path::test  Pass pytest paths or additional flags' \
	  '  make nix-venv-setup                 Create/update the test virtualenv' \
	  '  make nix-venv                       Open a shell in that virtualenv' \
	  '  make nix-build / nix-wheel         Build distributions / wheel only' \
	  '  make nix-install                   Install cpppo with optional dependencies' \
	  '  make nix-analyze / nix-pylint       Run linters' \
	  '  make clean                         Remove local build and Python cache files' \
	  '  See CLAUDE.md for interpreter, pytest, and serial options.'

# Use the flake's interpreter and GNU Make, even when invoked from another venv.
nix-%:
	nix develop "./$(if $(TARGET),#$(TARGET))" $(NIX_OPTS) --command make "$*"

# The stamp is written only after dependency installation succeeds. A failed
# install can be retried in the same environment.
venv-setup:
	@set -e; \
	venv="$(VENV)"; stamp="$$venv/.cpppo-installed"; \
	if ! "$$venv/bin/python" -c 'import sys' >/dev/null 2>&1; then \
	    rm -f "$$stamp"; \
	    if $(PYTHON) -c 'import sys; sys.exit(sys.version_info[0] != 2)'; then \
	        bootstrap="$(VENV_DIR)/.py27-bootstrap"; \
	        if ! PYTHONPATH="$$bootstrap" $(PYTHON) -c 'import virtualenv' >/dev/null 2>&1; then \
	            $(PYTHON) -m pip install --target "$$bootstrap" 'virtualenv==20.15.1'; \
	        fi; \
	        PYTHONPATH="$$bootstrap" $(PYTHON) -m virtualenv --no-periodic-update \
	            --app-data "$$bootstrap/app-data" $(VENV_OPTS) "$$venv"; \
	    else \
	        $(PYTHON) -m venv $(VENV_OPTS) "$$venv"; \
	    fi; \
	fi; \
	for input in Makefile MANIFEST.in setup.py version.py requirements*.txt; do \
	    if [ "$$input" -nt "$$stamp" ]; then rm -f "$$stamp"; break; fi; \
	done; \
	if [ ! -f "$$stamp" ]; then \
	    "$$venv/bin/python" -m pip install -c requirements-cpython27.txt '.[all,tests]'; \
	    touch "$$stamp"; \
	fi

venv: venv-setup
	@echo "Activating $(VENV)"
	@bash --init-file "$(VENV)/bin/activate" -i

# Keep options common to all pytest entry points. SERIAL_TEST is inherited or
# supplied on the make command line when the serial ports are configured.
PYTEST = TZ="$(TZ)" $(RUN_PYTHON) -m pytest $(PYTESTOPTS)

test: $(TEST_ENV)
	$(PYTEST) $(TEST_ARGS)

test-%: $(TEST_ENV)
	@files=(); \
	while IFS= read -r file; do files+=("$$file"); done < <( \
	    find . \( -name .git -o -name .venv -o -name build -o -name dist \) -prune \
	        -o -type f -name '*$*_test.py' -print | sort ); \
	if [ "$${#files[@]}" -eq 0 ]; then echo 'No test files match $*' >&2; exit 1; fi; \
	$(PYTEST) "$${files[@]}" $(TEST_ARGS)

unit-%: $(TEST_ENV)
	$(PYTEST) -k "$*" $(TEST_ARGS)

build: $(TEST_ENV)
	$(RUN_PYTHON) -m build --no-isolation --outdir "$(DIST_DIR)"

build-check: $(TEST_ENV)
	$(RUN_PYTHON) -m build --version

wheel: $(TEST_ENV)
	$(RUN_PYTHON) -m build --no-isolation --wheel --outdir "$(DIST_DIR)"

install: $(TEST_ENV)
	$(RUN_PYTHON) -m pip install -c requirements-cpython27.txt '.[all]'

install-%: $(TEST_ENV)
	$(RUN_PYTHON) -m pip install -c requirements-cpython27.txt -r requirements-$*.txt

analyze: $(TEST_ENV)
	$(RUN_PYTHON) -m flake8 -j 1 --max-line-length=110 \
	  --ignore=F401,E201,E202,E221,E223,E226,E231,E242,E272,E701,E702,W191,W291,W503,W293,W391,E \
	  --extend-exclude='__init__.py,.venv,.nix-py2-bootstrap,build,dist' .

pylint: $(TEST_ENV)
	$(RUN_PYTHON) -m pylint . --disable=W,C,R --ignore=.venv,.nix-py2-bootstrap,build,dist

clean:
	rm -rf MANIFEST build dist auto *.egg-info .pytest_cache
	find . \( -name .git -o -name .venv \) -prune \
	    -o -name '__pycache__' -prune -exec rm -rf {} + \
	    -o -name '*.pyc' -type f -exec rm -f {} +

print-%:
	@printf '%s\n' '$* = $($*)' "origin: $(origin $*)"
