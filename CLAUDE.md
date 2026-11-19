# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cpppo (Communication Protocol Python Parser and Originator) is a Python library for implementing binary communications protocol parsers using deterministic finite automata. The project primarily focuses on EtherNet/IP CIP (Common Industrial Protocol) communication with industrial controllers like Rockwell ControlLogix systems, along with Modbus/TCP support for PLC communication.

## Development with Nix and GNU Make

Run these commands from the checkout root with Nix flakes and `nix-command` enabled. The default shell uses CPython 3.13. Set `TARGET` to `py311`, `py312`, `py313`, `py314`, or `py27` to select another shell. The `nix-%` rule forwards any Make target to that shell.

```sh
make nix-test
make TARGET=py27 nix-test
make TARGET=py312 nix-test-enip
make nix-unit-client
make nix-test TEST_ARGS='server/enip/client_test.py::test_parse_path'
make nix-test PYTESTOPTS='-vv -ra --tb=short'
```

`test` runs the full pytest suite. `test-<pattern>` selects `*<pattern>_test.py` files, including nested suites. `unit-<pattern>` passes the pattern to `pytest -k`. `TEST_ARGS` accepts additional pytest arguments or paths. All three targets set `TZ=Canada/Mountain` and use `pytest.ini`.

The first Nix command that needs Python dependencies provisions `.venv/<interpreter>` using pip and installs `.[all,tests]`. Later runs reuse it and refresh dependencies after packaging inputs change. Python 2.7 uses `virtualenv` and pytest 4.6. Python 3 uses the standard-library `venv` module.

- `make nix-venv-setup` provisions the environment without opening an interactive shell.
- `make nix-venv` opens an activated Bash shell. From there `make test`, `make test-<pattern>`, and `make unit-<pattern>` use that interpreter.
- `make nix-build` builds a source distribution and wheel into `dist/`. `make nix-wheel` builds only the wheel. Set `DIST_DIR` to change the output directory.
- `make nix-install` reinstalls the current checkout with its optional dependencies. `make nix-install-dev` and `make nix-install-tests` install the corresponding requirements files.
- `make nix-analyze` and `make nix-pylint` run the linters in the selected environment. `make clean` removes build artifacts and Python caches and preserves the virtualenvs.

`nix develop .#py27` followed by `make test` is equivalent to `make TARGET=py27 nix-test`. Outside Nix, plain `make test` uses the interpreter on `PATH` and expects dependencies to be installed. Set `PYTHON` to select a different interpreter. `VENV_DIR` changes the directory for managed virtualenvs, and `VENV` overrides the path of one environment. `NIX_OPTS` passes flags to `nix develop`.

### Serial tests

The Python 3 suite runs the serial integration tests when `SERIAL_TEST` names a configured group of ports. Use `make SERIAL_TEST=ttyS0 nix-test-serial` for physical ports or `make SERIAL_TEST=ttyV0 nix-test-serial` for virtual ports. The number is the client port suffix. The next two ports are used as servers. On POSIX, run `nix develop --command python3 ttyV-setup.py 3` in a separate terminal to provide three virtual ports, then stop the bridge with Ctrl-C after the tests. The bridge replaces local `ttyV0` through `ttyV2` links.

### Class 1 interoperability

`make nix-test-class1` exercises the Class 1 scanner, printer adapter, watchdog, and separate Class 3 job channel in cpppo. For independent peers, the `interop` shell adds a C/C++ toolchain and CMake.

```sh
git clone https://github.com/nimbuscontrols/EIPScanner.git ~/src/EIPScanner
make TARGET=interop nix-test-class1-interop
```

The target uses the OpENer checkout at `~/src/OpENer` and EIPScanner at `~/src/EIPScanner`. Override `OPENER_SRC` or `EIPSCANNER_SRC` to point to another checkout. Verified peer revisions are OpENer `fb90c9918081c184b1876ce0c893168cf8b5653c` and EIPScanner `12c89a57ec2e7449efb1348be52af10be9ef9701`. The target builds temporary Git snapshots with loopback and macOS portability patches. EIPScanner's receive port is 2223 in the test build so it can share the host with OpENer. Keep TCP 44818 and UDP 2222 and 2223 free on loopback.

- The cpppo scanner opens OpENer's sample Input Only assembly, writes new sample data over explicit messaging, and verifies the changed cyclic input.
- EIPScanner opens the cpppo printer's Input Only assembly and verifies several snapshots containing the job number written over Class 3.
- EIPScanner opens OpENer's Input Only assembly and verifies the sample data it wrote over explicit messaging.

To reuse prebuilt peers, set `CPPPO_OPENER` to the OpENer sample executable and `CPPPO_EIPSCANNER` to the probe built from `tools/class1_reference_scanner.cpp`, then run `make nix-test-class1`.

### Installed packages and README examples

`make nix-test-readme` runs every Python source block in `README.org` and
compares its stdout with the named `RESULTS` entry. It starts the documented
Class 1 adapter and a local Modbus simulator. Keep TCP ports 1502 and 44818
and UDP port 2222 free on loopback.

```sh
make TARGET=py313 nix-build
make TARGET=interop nix-test-artifacts
```

`nix-test-artifacts` expects one cpppo wheel and one source archive in
`DIST_DIR`. It builds the reference peers and runs the Class 1 suite, printer
demo, and README checks from separate virtualenvs outside the checkout.

### Python 2.7 scope

The CPython 2.7 environment covers the protocol parser, EtherNet/IP simulators, history, and other compatible tests. The current PyModbus 3.8 integration and Modbus command-line tools require Python 3.9 or newer.

### CI and release

GitHub Actions tests CPython 3.11 through 3.14 and the legacy CPython 2.7 target through the Nix flake. CPython 3.11 is the minimum maintained Python 3 version. Existing installations on older Python releases can continue to use compatible features.

Branch CI and tagged releases use the same package verification workflow. A
version tag such as `v5.7.0` must match `version.py`. The release workflow
passes the verified distributions to a separate job that publishes through
the PyPI `pypi` Trusted Publishing environment.

### Optional Dependencies

The project has several optional dependency groups:
- `[modbus]` - Modbus TCP/RTU support via pymodbus
- `[logix]` - Alternative Logix I/O via pylogix
- `[serial]` - Serial communication support
- `[dev]` - Development tools
- `[timestamp]` - Timestamp handling
- `[all]` - All optional dependencies

## Architecture

### Core Components

1. **automata.py** - Deterministic finite automata implementation using greenery library
2. **server/enip/** - EtherNet/IP CIP protocol implementation
   - `main.py` - EtherNet/IP server entry point
   - `client.py` - EtherNet/IP client implementation
   - `parser.py` - Protocol message parsing
   - `device.py` - Device simulation capabilities
   - `logix.py` - Rockwell Logix-specific functionality
3. **remote/** - Remote PLC communication utilities
   - `plc.py` - Generic PLC communication
   - `plc_modbus.py` - Modbus-specific PLC communication
4. **history/** - Historical data management
5. **tools/** - Utility modules

### Key Entry Points

- `python -m cpppo.server.enip` - Start EtherNet/IP server
- `enip_server` - Console script for EtherNet/IP server
- `enip_client` - Console script for EtherNet/IP client
- `enip_get_attribute` - Console script for attribute reading
- `modbus_sim` - Modbus simulator (Python 3.9+)
- `modbus_poll` - Modbus polling utility (Python 3.9+)

### Protocol Support

- **EtherNet/IP CIP**: Industrial Ethernet protocol for communication with PLCs
- **Modbus/TCP and RTU**: TCP and serial communication for industrial devices
- **Support for Rockwell ControlLogix, MicroLogix controllers**

## Configuration

- EtherNet/IP server configurations in `*.cfg` files
- Default configurations in `server/enip/defaults.py`
- Pytest configuration in `pytest.ini`
- Package metadata in `setup.py`
