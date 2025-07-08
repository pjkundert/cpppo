# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cpppo (Communication Protocol Python Parser and Originator) is a Python library for implementing binary communications protocol parsers using deterministic finite automata. The project primarily focuses on EtherNet/IP CIP (Common Industrial Protocol) communication with industrial controllers like Rockwell ControlLogix systems, along with Modbus/TCP support for PLC communication.

## Build System and Common Commands

This project uses a GNUmakefile build system with Python setuptools. The main Python interpreter targets are Python 2.7 and Python 3.x.

### Core Development Commands

- `make test` - Run all unit tests (pytest-based)
- `make test-<pattern>` - Run specific tests matching pattern (e.g., `make test-enip`)
- `make unit-<pattern>` - Run specific unit tests by keyword (e.g., `make unit-client`)
- `make analyze` - Run flake8 linting on the codebase
- `make pylint` - Run pylint static analysis
- `make build` - Build wheel package
- `make install` - Install the package with all dependencies
- `make clean` - Remove build artifacts

### Testing Configuration

- Uses pytest with configuration in `pytest.ini`
- Tests assume `TZ=Canada/Mountain` timezone
- To run tests with serial support: `make SERIAL_TEST=1 test`
- Single test files can be run with: `python -m pytest <test_file.py>`

### Package Management

- `make install-dev` - Install development dependencies
- `make install-tests` - Install test dependencies
- `make venv` - Create and activate virtual environment
- `pip install cpppo[all]` - Install with all optional dependencies

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
- `modbus_sim` - Modbus simulator (Python 2 only)
- `modbus_poll` - Modbus polling utility (Python 2 only)

### Protocol Support

- **EtherNet/IP CIP**: Industrial Ethernet protocol for communication with PLCs
- **Modbus/TCP**: Serial communication protocol for industrial devices
- **Support for Rockwell ControlLogix, MicroLogix controllers**

## Development Workflow

1. Clone repository: `git clone git@github.com:pjkundert/cpppo.git`
2. Install dependencies: `make install install-dev install-tests`
3. Run tests: `make test`
4. Make changes and test: `make test-<relevant_pattern>`
5. Run linting: `make analyze`
6. Build package: `make build`

## Testing

- Tests use pytest framework
- All test files follow `*_test.py` naming convention
- Test configuration in `pytest.ini` includes custom logging format
- Tests can be run individually or by pattern matching
- Some tests require specific timezone settings (Canada/Mountain)

## Configuration

- EtherNet/IP server configurations in `*.cfg` files
- Default configurations in `server/enip/defaults.py`
- Pytest configuration in `pytest.ini`
- Package metadata in `setup.py`

## Virtual Environment Support

The project includes Nix shell support (`shell.nix`, `default.nix`) and traditional Python virtual environments. Use `make venv` to create a complete development environment.

## Docker and Virtualization

Docker configurations are available in the `docker/` directory with various container setups for different deployment scenarios.