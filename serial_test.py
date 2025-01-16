
#
# Cpppo -- Communication Protocol Python Parser and Originator
#
# Copyright (c) 2015, Hard Consulting Corporation.
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
__copyright__                   = "Copyright (c) 2015 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import json
import logging
import os
import random
import re
import subprocess
import sys
import time
import traceback

import pytest

#
# We require *explicit* access to the ./ttyS[012] serial ports to perform this test -- we must
# not assume that can safely use the serial port(s), or that they are configured for us to run our
# tests!  Therefore, we will run these tests ONLY if "serial" tests are explicitly called for
# (eg. 'make unit-serial' or 'make test-serial')
#
# They must be configured as RS485, in the following multi-drop pattern:
#
#     - master -      - slaves -----------------
#     ttyS0(COM1) --> ttyS1(COM2) --> ttyS2(COM3)
#
# The Modbus Master will be on ttyS0, and two Modbus slave-ids (unit numbers) will be simulated on
# each of ttyS1 and ttyS2.  Since they each must ignore requests to slave-ids they do not simulate,
# pymodbus >= 3.8.0 is required.
#

if sys.platform == 'win32':
    PORT_BASE_DEFAULT		= "COM"
    PORT_NUM_DEFAULT		= 3
else:
    PORT_BASE_DEFAULT		= "ttyS"
    PORT_NUM_DEFAULT		= 0

# Handles eg. "3" (start default port name at 3), "COM2", "ttyS", and even ""
PORT_BASE,PORT_NUM		= re.match( r'^(.*?)(\d*)$', os.environ.get( "SERIAL_TEST", "" )).groups()
PORT_NUM			= PORT_NUM or PORT_NUM_DEFAULT
PORT_BASE			= PORT_BASE or PORT_BASE_DEFAULT

PORT_MASTER			= "{PORT_BASE}{PORT_NUM}".format( PORT_BASE=PORT_BASE, PORT_NUM=PORT_NUM+0 )
PORT_SLAVE_1			= "{PORT_BASE}{PORT_NUM}".format( PORT_BASE=PORT_BASE, PORT_NUM=PORT_NUM+1 )
PORT_SLAVE_2			= "{PORT_BASE}{PORT_NUM}".format( PORT_BASE=PORT_BASE, PORT_NUM=PORT_NUM+2 )
PORT_SLAVES			= {
    PORT_SLAVE_1: [1,3],
    PORT_SLAVE_2: [2,4],
}

PORT_STOPBITS			= 1
PORT_BYTESIZE			= 8
PORT_PARITY			= "N"
PORT_BAUDRATE			= 57600 # 115200 # use slow serial to get some contention
PORT_TIMEOUT			= .05

PORT_LIST			= []
has_pyserial			= False
try:
    import serial
    import serial.tools.list_ports
    PORT_PARITY			= serial.PARITY_NONE
    PORT_LIST			= list( p.name for p in serial.tools.list_ports.comports() )
    has_pyserial		= True
except ImportError:
    logging.warning( "Failed to import pyserial module; skipping Modbus/RTU related tests; run 'pip install pyserial'" )

logging.warning( "Detected serial ports: {PORT_LIST!r}".format( PORT_LIST=PORT_LIST ))

has_minimalmodbus		= False
try:
    # Configure minimalmodbus to use the specified port serial framing
    import minimalmodbus
    has_minimalmodbus		= True
except ImportError:
    logging.warning( "Failed to import minimalmodbus; skipping some tests" )

has_pymodbus			= False
try:
    import pymodbus
    has_pymodbus		= True
except ImportError:
    logging.warning( "Failed to import pymodbus module; skipping Modbus/TCP related tests; run 'pip install pymodbus'" )

from .tools.waits import waitfor
from .modbus_test import start_modbus_simulator, has_o_nonblock, run_plc_modbus_polls
if has_pymodbus and has_pyserial:
    from .remote.pymodbus_fixes import modbus_client_rtu, Defaults
    from .remote.plc_modbus import poller_modbus


@pytest.mark.skipif( not has_pymodbus,
                     reason="Needs pymodbus" )
def test_pymodbus_version():
    """The serial_tests.py must have pymodbus >= 1.3, because we need to use ignore_missing_slaves.

    """
    version			= list( map( int, pymodbus.__version__.split( '.' )))
    expects			= [3,8,0]
    assert version >= expects, "Version of pymodbus is too old: %r; expected %r or newer" % (
        version, expects )


@pytest.mark.skipif(
    'SERIAL_TEST' not in os.environ or not has_pyserial or not has_pymodbus
    or not (( os.path.exists( PORT_MASTER )
              and any( os.path.exists( port ) for port in PORT_SLAVES ))
            or ( PORT_MASTER in PORT_LIST
                 and any( port in PORT_LIST for port in PORT_SLAVES ))),
    reason="Needs SERIAL_TEST and {PORT_MASTER} and pyserial and pymodbus and {slaves}; have {PORT_LIST}".format(
        PORT_MASTER=PORT_MASTER, slaves=','.join(PORT_SLAVES), PORT_LIST=', '.join( PORT_LIST ) or None
    )
)
def test_pymodbus_rs485_sync():
    """Raw pymodbus API to communicate via ttyS0 client --> ttyS{1,2,...} servers.  Supported when
    the client and at least one server RS-485 port is available.

    Since this test does not fire up simulators via subprocess, it works on Windows!

    """

    import asyncio
    import threading

    from contextlib import suppress

    from pymodbus.client import ModbusSerialClient
    from pymodbus.framer import FramerType
    from pymodbus.datastore import ModbusServerContext, ModbusSlaveContext, ModbusSparseDataBlock

    from .remote.pymodbus_fixes import modbus_server_rtu
    #from pymodbus.server import ModbusSerialServer as modbus_server_rtu

    serial_args = dict(
        timeout=PORT_TIMEOUT,
        # retries=3,
        baudrate = PORT_BAUDRATE,
        bytesize = PORT_BYTESIZE,
        parity = PORT_PARITY,
        stopbits = PORT_STOPBITS,
        # handle_local_echo=False,
    )

    async def server_start( port, units ):
        context			= ModbusServerContext(
            single	= False,
            slaves	= {
                unit: ModbusSlaveContext(
                    di=ModbusSparseDataBlock({a:v for a,v in enumerate(range(100))}),
                    co=ModbusSparseDataBlock({a:v%2 for a,v in enumerate(range(100))}),
                    hr=ModbusSparseDataBlock({a:v for a,v in enumerate(range(100))}),
                    ir=ModbusSparseDataBlock({a:v for a,v in enumerate(range(100))}),
                )
                for unit in units
            },
        )
        logging.warning( "Starting Modbus Serial server for units {units!r} on {port}".format(
            units=units, port=port ))

        server			= modbus_server_rtu(
            port	= port,
            context	= context,
            framer	= FramerType.RTU,
            ignore_missing_slaves = True,
            **serial_args,
        )

        # For later shutdown of the server, by port, using its asyncio event loop
        server_start.server_async_loop[port] = (server, asyncio.get_event_loop())
        with suppress(asyncio.exceptions.CancelledError):
            await server.serve_forever()
        logging.warning( "Stopping Modbus Serial server for units {units!r} on {port} w/ {context}".format(
            units=units, port=port, context=context ))

    server_start.server_async_loop = {}

    servers			= {}
    for port,units in PORT_SLAVES.items():
        logging.warning( "Threaded Modbus Serial server for units {units!r} on {port}".format(
            units=units, port=port ))
        servers[port]		= threading.Thread(
            target	= lambda port, units: asyncio.run( server_start( port, units )),
            kwargs	= dict(
                port	= port,
                units	= units,
            )
        )
        servers[port].daemon	= True
        servers[port].start()

    time.sleep(.5)

    # Try the bare Serial client(s), and then the locking version.  Should be identical.
    for cls in ModbusSerialClient, modbus_client_rtu:
        logging.warning( "Testing Modbus/RTU Serial client on {port}: {cls}".format(
            port=PORT_MASTER, cls=cls.__name__ ))
        client			= cls(
            port	= PORT_MASTER,
            framer	= FramerType.RTU,
            **serial_args,
        )
        client.connect()

        rr1			= client.read_coils( 1, count=1, slave=1 )
        rr3			= client.read_coils( 2, count=1, slave=3 )
        assert (( not rr3.isError() and rr3.bits[0] == False ) or
                ( not rr1.isError() and rr1.bits[0] == False ))
        rr2			= client.read_coils( 3, count=2, slave=3 )
        if not rr2.isError:  # 2nd RS-485 device optional...
            assert rr2.bits[0] == True and rr2.bits[1] == False and rr2.bits[2] == True

        rr99			= None
        with suppress(pymodbus.exceptions.ModbusIOException):
            rr99		= client.read_coils( 1, count=1, slave=99 )
        assert rr99 is None

        client.close()
        del client

    # Now ensure we can pound away from multiple threads using the locking client.
    client			= modbus_client_rtu(
        port	= PORT_MASTER,
        framer	= FramerType.RTU,
        **serial_args,
    )

    clients			= []
    def reader():
        logging.warning( "Testing Modbus/RTU Serial reader: {cls} on Thread {tid}".format(
            cls=client.__class__.__name__, tid=threading.current_thread().ident ))
        for a in range( 10 ):
            with client:
                units		= set()
                for port in servers:
                    units      |= set( PORT_SLAVES[port] )
                unit		= random.choice( list( units ))
                expect		= not bool( a%2 )
                rr		= client.read_coils( a, count=1, slave=unit )
                if not rr.isError():
                    logging.warning( "unit {unit} coil {a} == {value!r}".format( unit=unit, a=a, value=rr.bits ))
                if rr.isError() or rr.bits[0] != expect:
                    logging.warning( "Expected unit {unit} coil {a} == {expect}, got {val}".format(
                        unit=unit, a=a, expect=expect, val=( rr if rr.isError() else rr.bits[0] )))

    for _ in range( 2 ):
        clients.append(
            threading.Thread(
                target	= reader,
            )
        )
        clients[-1].daemon	= True
        clients[-1].start()

    for c in clients:
        c.join()
    for p in servers:
        s,l			= server_start.server_async_loop[p]
        asyncio.run_coroutine_threadsafe( s.shutdown(), l )
    for p in servers:
        servers[p].join()


RTU_TIMEOUT			= PORT_TIMEOUT  # latency while simulated slave awaits next incoming byte
def simulated_modbus_rtu( tty ):
    """Start a simulator on a serial device PORT_SLAVE, reporting as the specified slave(s) (any slave
    ID, if 'slave' keyword is missing or None); parse whether device successfully opened.  Pass any
    remaining kwds as config options.

    TODO: Implement RS485 inter-character and pre/post request timeouts properly.  Right now, the
    simulator just waits forever for the next character and tries to frame requests.  It should fail
    a request if it ever sees an inter-character delay of > 1.5 character widths, and it also
    expects certain delays before/after requests.

    """
    return start_modbus_simulator(
        '-vvv', '--log', '.'.join( [
            'serial_test', 'modbus_sim', 'log', os.path.basename( tty )] ),
        #'--evil', "delay:{DELAY_LO}-{DELAY_HI}".format( DELAY_LO=RTU_TIMEOUT/10, DELAY_HI=RTU_TIMEOUT/2 ),
        '--address', tty,
        '    1 -  1000 = 1,0',
        '40001 - 41000 = 1,2,3,4,5,6,7,8,9,0',
        # Configure Modbus/RTU simulator to use specified port serial framing
        '--config', json.dumps( {
            'stopbits': PORT_STOPBITS,
            'bytesize': PORT_BYTESIZE,
            'parity':   PORT_PARITY,
            'baudrate': PORT_BAUDRATE,
            'slaves':	PORT_SLAVES[tty],
            'timeout':  RTU_TIMEOUT, # TODO: implement meaningfully; basically ignored
            'ignore_missing_slaves': True,
        } )
    )


@pytest.fixture( scope="module" )
def simulated_modbus_rtu_ttyS1( request ):
    command,address		= simulated_modbus_rtu( PORT_SLAVE_1 )
    request.addfinalizer( command.kill )
    return command,address


@pytest.fixture( scope="module" )
def simulated_modbus_rtu_ttyS2( request ):
    command,address		= simulated_modbus_rtu( PORT_SLAVE_2 )
    request.addfinalizer( command.kill )
    return command,address


@pytest.mark.skipif(
    'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_minimalmodbus or not has_pyserial
    or not (( os.path.exists(PORT_MASTER) and os.path.exists( PORT_SLAVE_1 ))
            or ( PORT_MASTER in PORT_LIST and PORT_SLAVE_1 in PORT_LIST )),
    reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK ({has_o_nonblock}) and minimalmodbus ({has_minimalmodbus}) and pyserial, and {PORT_BASE}[{PORT_NUMS}]".format(
        has_o_nonblock=has_o_nonblock, has_minimalmodbus=has_minimalmodbus,
        PORT_BASE=PORT_BASE, PORT_NUMS=''.join(map(str, range(PORT_NUM, PORT_NUM+2))))
)
def test_rs485_basic( simulated_modbus_rtu_ttyS1 ):
    """Use MinimalModbus to test RS485 read/write.  The minimalmodbus API doesn't use 1-based Modbus data
    addressing, but zero-based Modbus/RTU command addressing."""

    command,address		= simulated_modbus_rtu_ttyS1

    comm			= minimalmodbus.Instrument( port=PORT_MASTER, slaveaddress=1 )
    comm.serial.stopbits	= PORT_STOPBITS
    comm.serial.bytesize	= PORT_BYTESIZE
    comm.serial.parity		= PORT_PARITY
    comm.serial.baudrate	= PORT_BAUDRATE
    comm.serial.timeout		= PORT_TIMEOUT

    logging.warning( "{instrument!r}".format( instrument=comm ))
    comm.debug			= True
    val				= comm.read_register( 0 )
    assert val == 1
    comm.write_register( 0, 99 )
    val				= comm.read_register( 0 )
    assert val == 99
    comm.write_register( 0, 1 )


@pytest.mark.skipif(
    'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_minimalmodbus or not has_pyserial
    or not (( os.path.exists(PORT_MASTER) and os.path.exists( PORT_SLAVE_1 ))
            or ( PORT_MASTER in PORT_LIST and PORT_SLAVE_1 in PORT_LIST )),
    reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK and minimalmodbus and pyserial, and {PORT_BASE}[{PORT_NUMS}]".format(
        PORT_BASE=PORT_BASE, PORT_NUMS=''.join(map(str, range(PORT_NUM, PORT_NUM+2))))
)
def test_rs485_read( simulated_modbus_rtu_ttyS1 ):
    """Use pymodbus to test RS485 read/write to a simulated device.

    These raw pymodbus API calls deal in zero-basis wire-protocol addresses (first protocol-level
    register address is 0, ...), NOT in Modbus register addressing (first Modbus register address is
    1, ...)

    Also, remember that the raw read_coils returns a number of values rounded up to a multiple of 8
    -- and any bit values NOT requested in the original request are *undefined*, and should be
    ignored!

    """

    command,address		= simulated_modbus_rtu_ttyS1
    Defaults.Timeout		= PORT_TIMEOUT
    client			= modbus_client_rtu(
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE, timeout=PORT_TIMEOUT,
    )

    for a in range( 10 ):
        unit			= 1
        expect			= not bool( a%2 )  # Modbus Coil 1 == 1 (at wire-protocol address 0)
        count			= 1
        logging.info( "unit {unit} coil {a} --> read {count}".format( unit=unit, a=a, count=count ));
        rr			= client.read_coils( a, count=count, slave=unit )
        if not rr.isError():
            logging.warning( "unit {unit} coil {a} == {value!r}".format( unit=unit, a=a, value=rr.bits ))
        assert (not rr.isError()) and rr.bits[0] == expect, \
            "Expected unit {unit} coil {a} == {expect}, got {val}".format(
                unit=unit, a=a, expect=expect, val=( rr if rr.isError() else rr.bits[0] ))


@pytest.mark.skipif(
    'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_pymodbus or not has_pyserial
    or not (( os.path.exists(PORT_MASTER) and os.path.exists( PORT_SLAVE_1 ))
            or ( PORT_MASTER in PORT_LIST and PORT_SLAVE_1 in PORT_LIST )),
    reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK and pymodbus, and {PORT_BASE}[{PORT_NUMS}]".format(
        PORT_BASE=PORT_BASE, PORT_NUMS=''.join(map(str, range(PORT_NUM, PORT_NUM+2))))
)
def test_rs485_poll( simulated_modbus_rtu_ttyS1 ):
    """Multiple poller_modbus instances may be polling different slave RTUs at different unit IDs.

    """
    command,address		= simulated_modbus_rtu_ttyS1
    Defaults.Timeout		= PORT_TIMEOUT
    client			= modbus_client_rtu(
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE, timeout=PORT_TIMEOUT,
    )

    time.sleep( .5 )
    unit			= 1
    plc				= poller_modbus( "RS485 unit %s" % ( unit ), client=client, unit=unit, rate=.25 )

    wfkw			= dict( timeout=plc.rate*2, intervals=10 )

    try:
        plc.write(     1, 0 )
        plc.write( 40001, 0 )
        plc.poll(  40001 )
        time.sleep( .5 )
        def is_there( reg ):
            val			= plc.read( reg )
            logging.info( f"is_there( {reg} ): {val!r} ==> {val is not None}" )
            return val is not None
        success,elapsed		= waitfor( lambda: is_there( 40001 ), "40001 polled", **wfkw )
        logging.info( f"is_there: {success}, ela: {elapsed}" )
        success,elapsed		= waitfor( lambda: plc.read( 40001 ) is not None, "40001 polled", **wfkw )
        logging.info( f"plc.read: {success}, ela: {elapsed}" )
        #assert plc.read( 40001 ) == None
        assert success
        assert elapsed < 1.0
        assert plc.read( 40001 ) == 0

        assert plc.read(     1 ) == None
        assert plc.read( 40002 ) == None
        success,elapsed		= waitfor( lambda: plc.read( 40002 ) is not None, "40002 polled", **wfkw )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40002 ) == 2
        success,elapsed		= waitfor( lambda: plc.read(     1 ) is not None, "00001 polled", **wfkw )
        assert success
        assert elapsed < 1.0
        assert plc.read(     1 ) == 0

        plc.write( 40001, 99 )
        success,elapsed		= waitfor( lambda: plc.read( 40001 ) == 99, "40001 polled", **wfkw )
        assert success
        assert elapsed < 1.0

        # See if we converge on our target poll time
        count			= plc.counter
        while plc.counter < count + 20:
            logging.normal( "%s at poll %d: Load: %s ", plc.description, plc.counter, plc.load )
            time.sleep( .5 )
        logging.normal( "%s at poll %d: Load: %s ", plc.description, plc.counter, plc.load )

    except Exception:
        logging.warning( "%s poller failed: %s", plc.description, traceback.format_exc() )
        raise
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
        waitfor( lambda: not plc.is_alive(), "%s poller done" % ( plc.description ), timeout=1.0 )


@pytest.mark.skipif(
    'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_pymodbus or not has_pyserial
    or not (( os.path.exists(PORT_MASTER) and os.path.exists( PORT_SLAVE_1 ) and os.path.exists( PORT_SLAVE_2 ))
            or ( PORT_MASTER in PORT_LIST and PORT_SLAVE_1 in PORT_LIST and PORT_SLAVE_2 in PORT_LIST )),
    reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK and pymodbus and pyserial, and {PORT_BASE}[{PORT_NUMS}]".format(
        PORT_BASE=PORT_BASE, PORT_NUMS=''.join(map(str, range(PORT_NUM, PORT_NUM+3))))
)

def test_rs485_multi( simulated_modbus_rtu_ttyS1,  simulated_modbus_rtu_ttyS2 ):

    command,address		= simulated_modbus_rtu_ttyS1
    command,address		= simulated_modbus_rtu_ttyS2
    Defaults.Timeout		= PORT_TIMEOUT
    client			= modbus_client_rtu(
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE, timeout=PORT_TIMEOUT,
    )

    # 4 poller_modbus instances sharing the same RTU Master 'client'.  They will all block on I/O
    # access via the same RS485 media interface.
    slaves			= [1,2,3,4]
    plc				= {}
    rate			= .25
    for unit in slaves:
        plc[unit]		= poller_modbus( "RS485 unit %s" % ( unit ), client=client, unit=unit, rate=rate )

    wfkw			= dict( timeout=rate * 2, intervals=10 )

    try:
        for unit in slaves:
            plc[unit].write(     1,  0 )
            plc[unit].write( 40001,  0 )
            plc[unit].poll(  40001 )

        # See if we converge on our target poll time
        count			= plc[slaves[0]].counter
        while any( plc[unit].counter < count + 20 for unit in slaves ):
            for unit in slaves:
                logging.normal( "%s at poll %d: Load: %s ", plc[unit].description, plc[unit].counter, plc[unit].load )
            time.sleep( .5 )
        for unit in slaves:
            logging.normal( "%s at poll %d: Load: %s ", plc[unit].description, plc[unit].counter, plc[unit].load )


        for unit in slaves:
            success,elapsed	= waitfor( lambda: plc[unit].read( 40001 ) is not None, "%d/40001 polled" % ( unit ), **wfkw )
            assert success
            assert elapsed < 1.0
            assert plc[unit].read( 40001 ) == 0

        # Haven't polled 1 or 40002 yet; start.
        for unit in slaves:
            assert plc[unit].read(     1 ) == None
            assert plc[unit].read( 40002 ) == None
        time.sleep(.5)
        for unit in slaves:
            success, elapsed	= waitfor( lambda: plc[unit].read( 40002 ) is not None, "%d/40002 polled" % ( unit ), **wfkw )
            assert success
            assert elapsed < 1.0
            assert plc[unit].read( 40002 ) == 2

            success,elapsed	= waitfor( lambda: plc[unit].read(     1 ) is not None, "%d/00001 polled" % ( unit ), **wfkw )
            assert success
            assert elapsed < 1.0
            assert plc[unit].read(     1 ) == 0

        for unit in slaves:
            plc[unit].write( 40001,   99 )
            success,elapsed	= waitfor( lambda: plc[unit].read( 40001 ) == 99, "%d/40001 polled" % ( unit ), **wfkw )
            assert success
            assert elapsed < 1.0

    except Exception:
        logging.warning( "poller failed: %s", traceback.format_exc() )
        raise
    finally:
        logging.info( "Stopping plc polling" )
        for unit in slaves:
            plc[unit].done	= True
        for unit in slaves:
            waitfor( lambda: not plc[unit].is_alive(), "%s poller done" % ( plc[unit].description ), timeout=1.0 )


@pytest.mark.skipif(
    'SERIAL_TEST' not in os.environ or not has_pymodbus or not has_pyserial or not has_o_nonblock
    or not (( os.path.exists(PORT_MASTER) and os.path.exists( PORT_SLAVE_1 ))
            or ( PORT_MASTER in PORT_LIST and PORT_SLAVE_1 in PORT_LIST )),
    reason="Needs SERIAL_TEST and pymodbus and pyserial and fcntl/O_NONBLOCK, and {PORT_BASE}[{PORT_NUMS}]".format(
        PORT_BASE=PORT_BASE, PORT_NUMS=''.join(map(str, range(PORT_NUM, PORT_NUM+3))))
)
def test_rs485_modbus_polls( simulated_modbus_rtu_ttyS1, simulated_modbus_rtu_ttyS2 ):
    Defaults.Timeout		= PORT_TIMEOUT
    # Set a default poll rate of 1.0s for new registers, and a reach of 10.
    command,(host,port)		= simulated_modbus_rtu_ttyS1
    unit			= PORT_SLAVES[host][0] # pick one of the units on this simulator
    client			= modbus_client_rtu(
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE, timeout=PORT_TIMEOUT,
    )
    plc				= poller_modbus( "RS485 unit %s" % unit, client=client, unit=unit, reach=10, rate=1.0 )
    try:
        run_plc_modbus_polls( plc )
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
        waitfor( lambda: not plc.is_alive(), "RS485 unit %s done" % unit, timeout=1.0 )

