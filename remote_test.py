
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2013, Hard Consulting Corporation.
# 
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
# 
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import logging
import threading
import time

import pytest

from .tools.waits import waitfor
from .modbus_test import start_modbus_simulator, has_o_nonblock, run_plc_modbus_polls
from .remote.plc import poller_simulator, PlcOffline
from .remote.io	import motor

log				= logging.getLogger(__name__)

TCP_TIMEOUT			= .1

has_pymodbus			= False
try:
    import pymodbus
    from pymodbus.exceptions import ModbusIOException
    from .remote.plc_modbus import poller_modbus, merge, shatter
    from .remote.pymodbus_fixes import modbus_client_tcp, Defaults
    has_pymodbus		= True
except ImportError as exc:
    logging.warning( "Failed to import pymodbus module; skipping Modbus/TCP related tests; run 'pip install pymodbus': {exc}".format( exc=exc ))


@pytest.fixture( scope="module" )
def simulated_modbus_tcp( request ):
    """Start a simulator over a range of ports; parse the port successfully bound.  Downstream fixtures
    require the i'face to be a str.

    """
    return modbus_simulator(request, '{:.3f}-{:.3f}'.format(TCP_TIMEOUT / 10, TCP_TIMEOUT / 2))


def modbus_simulator(request, delay):
    command,(iface,port)	= start_modbus_simulator(
        '-vvv', '--log', 'remote_test.modbus_sim.log.localhost:0',
        '--evil', 'delay:' + delay,
        '--address', 'localhost:0',
        #'--range', '10',
        '    1 -  1000 = 1,0',
        '40001 - 41000 = 1,2,3,4,5,6,7,8,9,0',
    )
    request.addfinalizer( command.kill )
    return command,(str(iface),port)


@pytest.mark.skipif( not has_pymodbus, reason="Needs pymodbus" )
def test_pymodbus_version():
    """The remote_tests.py can handle pymodbus >= 1.2, because we patch it for what we need, and don't
    use ignore_missing_slaves.

    """
    version			= list( map( int, pymodbus.__version__.split( '.' )))
    expects			= [3,8,0]
    assert version >= expects, "Version of pymodbus is too old: %r; expected %r or newer" % (
        version, expects )


@pytest.mark.skipif( not has_pymodbus, reason="Needs pymodbus" )
def test_pymodbus_listen( simulated_modbus_tcp ):
    # The communication callback announces the address once the async server binds.
    _command,(iface,port) = simulated_modbus_tcp
    client = modbus_client_tcp( host=iface, port=port )
    try:
        assert client.connect()
    finally:
        client.close()


def test_device():
    p				= poller_simulator( "PLC 1", rate=.5 )
    m				= motor( "chest", "M1", "Pressure Motor 1",
                                         plc=p, auto=100001, running=100002, start=1, 
                                         fault=100003, reset=100004, estop=100005 )
    waitfor( lambda: m.auto == 0, "m.auto polled" )
    assert m.auto == 0
    assert m.start == 0
    m.start = True
    waitfor( lambda: m.start == 1, "m.start = True" )
    assert m.start
    assert p.read( 1 ) == 1
    p.write( 100002, 1 )
    waitfor( lambda: m.running == 1, "10002 <== 1" )
    assert m.running


@pytest.mark.skipif( not has_pymodbus, reason="Needs pymodbus" )
def test_plc_merge():
    """ plc utility functions for merging/shattering Modbus address ranges """
    assert list( shatter( *(1,8), limit=3 )) == [(1,3), (4,3), (7,2) ]
    assert list( merge( [ (1,2), (2,3) ] )) == [ (1,4) ]
    assert list( merge( [ (1,2), (2,3), (6,6), (40001,5) ] )) == [ (1,4), (6,6), (40001,5) ]
    assert list( merge( [ (1,2), (2,3), (6,6), (40001,5) ], reach=5 )) \
        == [ (1,11), (40001,5) ]
    assert list( merge( [ (1,2), (2,3), (6,6), (40001,5) ], reach=5, limit=5 )) \
        == [ (1,5), (6,5), (11,1), (40001,5) ]
    # Test avoidance of merging different register types.
    assert list( merge( [ (9998,1), (9999,1), (10000,1) ], reach=5, limit=5 )) \
        == [ (9998,2), (10000,1)]

    assert list( merge( [(1,130), (140,4), (232,170), (40001,100)], reach=5 )) \
        == [(1,130), (140,4), (232,170), (40001,100)]


@pytest.mark.skipif( not has_pymodbus or not has_o_nonblock, reason="Needs pymodbus and fcntl/O_NONBLOCK" )
def test_plc_modbus_basic( simulated_modbus_tcp, monkeypatch ):
    _command,(iface,port) = simulated_modbus_tcp
    monkeypatch.setattr( Defaults, 'Timeout', TCP_TIMEOUT )
    client = modbus_client_tcp( host=iface, port=port )
    plc = poller_modbus( "Motor PLC", client=client )
    try:
        plc.write( 1, 1 )
    finally:
        plc.done = True
        waitfor( lambda: not plc.is_alive(), "Motor PLC poller done" )
        client.close()


@pytest.mark.skipif( not has_pymodbus or not has_o_nonblock, reason="Needs pymodbus and fcntl/O_NONBLOCK" )
def test_plc_modbus_timeouts( request, monkeypatch ):
    _command,(iface,port) = modbus_simulator( request, '0.2' )
    client = modbus_client_tcp( host=iface, port=port, retries=0 )
    plc = poller_modbus( "Motor PLC", client=client )
    try:
        monkeypatch.setattr( Defaults, 'Timeout', 0.06 )
        with pytest.raises( ModbusIOException, match="No response received" ):
            plc.write( 1, 1 )

        # Discard the connection with the delayed response before trying again.
        client.close()
        monkeypatch.setattr( Defaults, 'Timeout', 1.0 )
        plc.write( 1, 1 )
    finally:
        plc.done = True
        waitfor( lambda: not plc.is_alive(), "Motor PLC poller done" )
        client.close()


@pytest.mark.skipif( not has_pymodbus or not has_o_nonblock, reason="Needs pymodbus and fcntl/O_NONBLOCK" )
def test_plc_modbus_nonexistent( simulated_modbus_tcp ):
    Defaults.Timeout		= TCP_TIMEOUT
    command,(iface,port)	= simulated_modbus_tcp
    client			= modbus_client_tcp( host=iface, port=port+1 )
    plc_bad			= poller_modbus( "Motor PLC", client=client ) # Wrong port
    try:
        plc_bad.write( 1, 1 )
        raise Exception( 
            "Write should have failed due to connection failure after %7.3f seconds" % (
                Defaults.Timeout ))
    except PlcOffline as exc:
        log.info( "Write transaction timed out (bad plc) as expected: %s", exc )
        assert str( exc ).find( "failed: Offline" )
    except Exception as exc:
        log.warning( "Failed due to unexpected exception: %s", exc )
        raise
    finally:
        log.info( "Stopping plc polling" )
        plc_bad.done		= True
        waitfor( lambda: not plc_bad.is_alive(), "Motor PLC poller done" )


@pytest.mark.skipif( not has_pymodbus or not has_o_nonblock, reason="Needs pymodbus and fcntl/O_NONBLOCK" )
def test_plc_modbus_polls( simulated_modbus_tcp ):
    Defaults.Timeout		= TCP_TIMEOUT # PLC simulator has .1x-.5x delay
    # Set a default poll rate of 1.0s for new registers, and a reach of 10.
    command,(iface,port)	= simulated_modbus_tcp
    client			= modbus_client_tcp( host=iface, port=port )
    plc				= poller_modbus( "Motor PLC", client=client, reach=10, rate=1.0 )
    try:
        run_plc_modbus_polls( plc )
    finally:
        log.info( "Stopping plc polling" )
        plc.done		= True
        waitfor( lambda: not plc.is_alive(), "Motor PLC poller done", timeout=1.0 )
