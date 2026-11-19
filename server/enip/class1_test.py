"""Class 1 and Class 3 on a printer simulator with independent TCP and UDP sockets."""

from __future__ import absolute_import

import ast
import contextlib
import os
import select
import socket
import struct
import subprocess
import sys
import time

import pytest

from . import class1, client
from .printer_example import PROFILE


@pytest.fixture
def printer():
    source_parent = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
    command = subprocess.Popen(
        [sys.executable, '-m', 'cpppo.server.enip.printer_example',
         '--address', '127.0.0.1:0', '--io-address', '127.0.0.1:0', '--no-udp', '-A'],
        cwd=source_parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        assert select.select([command.stdout], [], [], 10)[0], "Printer startup timed out"
        line = command.stdout.readline()
        assert line.startswith(b'Network TCP Server address = '), line
        yield ast.literal_eval(line.decode('ascii').split(' = ', 1)[1])
    finally:
        command.terminate()
        command.communicate()


def test_class1_datagram():
    frame = bytes(bytearray.fromhex('0200028008000403020108070605b10005002211334142'))
    assert class1.decode_io(frame) == (0x01020304, 0x05060708, 0x1122, b'3AB')
    assert class1.encode_io(0x01020304, 0x05060708, 0x1122, b'3AB') == frame
    with pytest.raises(ValueError):
        class1.decode_io(frame[:-1])


def test_class1_printer(printer):
    host, port = printer
    with contextlib.closing(client.implicit(
            host, port=port, timeout=2, transport_class=1, io_profile=PROFILE)) as scanner:
        assert scanner.receive_io(timeout=2) == b'\0' * PROFILE.input_size
        assert scanner.established.forward_open.T_O.API == 50000
        with contextlib.closing(client.implicit(host, port=port, timeout=2)) as explicit:
            with explicit:
                operations = client.parse_operations(
                    ['PrinterFlags=(USINT)3', 'PaperLevel=(USINT)75', 'SubmitJob=(UDINT)42'])
                failures, _ = explicit.process(operations, timeout=2)
                assert failures == 0

        expected = struct.pack('<BBHI', 3, 75, 0, 42)
        end = class1.clock() + 2
        while scanner.receive_io() != expected and class1.clock() < end:
            time.sleep(.01)
        assert scanner.receive_io() == expected

    # Forward Close releases the single adapter connection slot.
    with contextlib.closing(client.implicit(
            host, port=port, timeout=2, transport_class=1, io_profile=PROFILE)) as scanner:
        assert scanner.receive_io(timeout=2) == expected


def test_class1_rejects_wrong_size(printer):
    host, port = printer
    wrong_profile = class1.InputOnly(151, 152, 100, PROFILE.input_size + 1)
    with pytest.raises(AssertionError, match="Failed to receive successful Forward Open"):
        client.implicit(host, port=port, timeout=2, transport_class=1, io_profile=wrong_profile)


def test_class1_watchdog_releases_adapter(printer):
    host, port = printer
    def connect():
        return client.implicit(host, port=port, timeout=2, transport_class=1, io_profile=PROFILE)

    with contextlib.closing(connect()) as original:
        assert original.receive_io(timeout=2) is not None
        # Stop UDP heartbeats with the TCP session still open.
        original.io.close()
        assert original.receive_io() is None
        deadline = class1.clock() + 2
        while True:
            try:
                replacement = connect()
                break
            except AssertionError:
                if class1.clock() >= deadline:
                    raise
                time.sleep(.025)
        with contextlib.closing(replacement):
            assert replacement.receive_io(timeout=2) is not None


@pytest.fixture
def opener(tmpdir):
    executable = os.environ.get('CPPPO_OPENER')
    if not executable:
        pytest.skip("Set CPPPO_OPENER to the OpENer sample executable")
    interface = os.environ.get('CPPPO_OPENER_INTERFACE', 'lo0' if sys.platform == 'darwin' else 'lo')
    sample_address = ('127.0.0.1', 44818)
    child = subprocess.Popen([executable, interface], cwd=str(tmpdir))
    try:
        end = class1.clock() + 5
        while True:
            assert child.poll() is None, "OpENer exited during startup"
            try:
                with contextlib.closing(socket.create_connection(sample_address, timeout=.1)):
                    break
            except socket.error:
                if class1.clock() >= end:
                    raise
                time.sleep(.05)
        yield sample_address
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait()


@pytest.fixture
def eipscanner():
    executable = os.environ.get('CPPPO_EIPSCANNER')
    if not executable:
        pytest.skip("Set CPPPO_EIPSCANNER to the built reference scanner")
    return executable


def test_class1_cpppo_scanner_opener_adapter(opener):
    host, port = opener
    profile = class1.InputOnly(151, 152, 100, 32)
    with contextlib.closing(client.implicit(
            host, port=port, timeout=2, transport_class=1, io_profile=profile)) as scanner:
        assert scanner.receive_io(timeout=2) == b'\0' * 32
        sample = list(range(32))
        with contextlib.closing(client.connector(host, port=port, timeout=2)) as explicit:
            with explicit:
                explicit.set_attribute_single('@4/150/3', sample, elements=32,
                                              route_path=False, send_path='', timeout=2)
                response, _ = client.await_response(explicit, timeout=2)
            assert client.enip_replies(response)[0].status == 0
        expected = bytes(bytearray(sample))
        end = class1.clock() + 2
        while scanner.receive_io() != expected and class1.clock() < end:
            time.sleep(.01)
        assert scanner.receive_io() == expected


def test_class1_eipscanner_originator_cpppo_adapter(eipscanner, printer):
    host, port = printer
    with contextlib.closing(client.implicit(host, port=port, timeout=2)) as explicit:
        operations = client.parse_operations(
            ['PrinterFlags=(USINT)3', 'PaperLevel=(USINT)75', 'SubmitJob=(UDINT)42'])
        with explicit:
            failures, _ = explicit.process(operations, timeout=2)
        assert failures == 0
    subprocess.check_call([eipscanner, str(port), 'cpppo'], timeout=10)


def test_class1_eipscanner_opener(eipscanner, opener):
    subprocess.check_call([eipscanner, str(opener[1]), 'opener'], timeout=10)
