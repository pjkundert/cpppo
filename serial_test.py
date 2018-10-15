
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
import subprocess
import time
import traceback

import pytest

# 
# We require *explicit* access to the /dev/ttys[012] serial ports to perform this test -- we must
# not assume that can safely use the serial port(s), or that they are configured for us to run our
# tests!  Therefore, we will run these tests ONLY if "serial" tests are explicitly called for
# (eg. 'make unit-serial' or 'make test-serial')
#
# They must be configured as RS485, in the following multi-drop pattern:
#
#     - master -      - slaves -----------------
#     ttyS1(COM2) --> ttys0(COM1) --> ttys2(COM3)
# 
# The Modbus Master will be on ttyS1, and two Modbus slave-ids (unit numbers) will be simulated on
# each of ttyS0 and ttyS2.  Since they each must ignore requests to slave-ids they do not simulate,
# pymodbus >= 1.3.0 is required.
# 
PORT_MASTER			= "/dev/ttyS1"
PORT_SLAVES			= {
    "/dev/ttyS0": [2,4],
    "/dev/ttyS2": [1,3],
}

PORT_STOPBITS			= 1
PORT_BYTESIZE			= 8
PORT_PARITY			= None
PORT_BAUDRATE			= 9600 # 19200 # 115200 # use slow serial to get some contention
PORT_TIMEOUT			= 1.5

has_pyserial			= False
try:
    import serial
    PORT_PARITY			= serial.PARITY_NONE
    has_pyserial		= True
except ImportError:
    logging.warning( "Failed to import pyserial module; skipping Modbus/RTU related tests; run 'pip install pyserial'" )
    
has_minimalmodbus		= False
try:
    # Configure minimalmodbus to use the specified port serial framing
    import minimalmodbus
    minimalmodbus.STOPBITS	= PORT_STOPBITS
    minimalmodbus.BYTESIZE	= PORT_BYTESIZE
    minimalmodbus.PARITY	= PORT_PARITY
    minimalmodbus.BAUDRATE	= PORT_BAUDRATE
    minimalmodbus.TIMEOUT	= PORT_TIMEOUT

    has_minimalmodbus		= True
except ImportError:
    logging.warning( "Failed to import minimalmodbus; skipping some tests" )

has_pymodbus			= False
try:
    import pymodbus
    from pymodbus.constants import Defaults
    has_pymodbus		= True
except ImportError:
    logging.warning( "Failed to import pymodbus module; skipping Modbus/TCP related tests; run 'pip install pymodbus'" )

from .tools.waits import waitfor
from .modbus_test import start_modbus_simulator, has_o_nonblock, run_plc_modbus_polls
if has_pymodbus and has_pyserial:
    from .remote.pymodbus_fixes import modbus_client_rtu, modbus_rtu_framer_collecting
    from .remote.plc_modbus import poller_modbus


@pytest.mark.skipif( not has_pymodbus,
                     reason="Needs pymodbus" )
def test_pymodbus_version():
    """The serial_tests.py must have pymodbus >= 1.3, because we need to use ignore_missing_slaves.

    """
    version			= list( map( int, pymodbus.__version__.split( '.' )))
    expects			= [1,3,0]
    assert version >= expects, "Version of pymodbus is too old: %r; expected %r or newer" % (
        version, expects )


RTU_TIMEOUT			= 0.1  # latency while simulated slave awaits next incoming byte
def simulated_modbus_rtu( tty ):
    """Start a simulator on a serial device PORT_SLAVE, reporting as the specified slave(s) (any slave
    ID, if 'slave' keyword is missing or None); parse whether device successfully opened.  Pass any
    remaining kwds as config options.

    TODO: Implement RS485 inter-character and pre/post request timeouts properly.  Right now, the
    simulator just waits forever for the next character and tries to frame requests.  It should fail
    a request if it ever sees an inter-character delay of > 1.5 character widths, and it also
    expects certain delays before/after requests.

    """
    return start_modbus_simulator( options=[
        '-vvv', '--log', '.'.join( [
            'serial_test', 'modbus_sim', 'log', os.path.basename( tty )] ),
        '--evil', 'delay:.01-.1',
        '--address', tty,
        '    1 -  1000 = 0',
        '40001 - 41000 = 0',
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
    ] )

@pytest.fixture( scope="module" )
def simulated_modbus_rtu_ttyS0():
    return simulated_modbus_rtu( "/dev/ttyS0" )

@pytest.fixture( scope="module" )
def simulated_modbus_rtu_ttyS2():
    return simulated_modbus_rtu( "/dev/ttyS2" )

@pytest.mark.skipif( 'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_minimalmodbus or not has_pyserial,
                     reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK and minimalmodbus and pyserial" )
def test_rs485_basic( simulated_modbus_rtu_ttyS0 ):
    """Use MinimalModbus to test RS485 read/write. """

    groups			= subprocess.check_output( ['groups'] )
    assert 'dialout' in groups, \
        "Ensure that the user is in the dialout group; run 'addgroup %s dialout'" % (
            os.environ.get( 'USER', '(unknown)' ))

    command,address		= simulated_modbus_rtu_ttyS0

    comm			= minimalmodbus.Instrument( port=PORT_MASTER, slaveaddress=2 )
    comm.debug			= True
    val				= comm.read_register( 1 )
    assert val == 0
    comm.write_register( 1, 99 )
    val				= comm.read_register( 1 )
    assert val == 99
    comm.write_register( 1, 0 )



@pytest.mark.skipif( 'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_pymodbus or not has_pyserial,
                     reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK and pymodbus and pyserial" )
def test_rs485_poll( simulated_modbus_rtu_ttyS0 ):
    """Multiple poller_modbus instances may be polling different slave RTUs at different unit IDs.

    """
    command,address		= simulated_modbus_rtu_ttyS0
    Defaults.Timeout		= PORT_TIMEOUT
    client			= modbus_client_rtu( framer=modbus_rtu_framer_collecting,
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE )

    unit			= 2
    plc				= poller_modbus( "RS485 unit %s" % ( unit ), client=client, unit=unit, rate=.25 )

    wfkw			= dict( timeout=1.0, intervals=10 )

    try:
        plc.write( 1, 0 )
        plc.write( 40001, 0 )

        plc.poll( 40001 )

        success,elapsed		= waitfor( lambda: plc.read( 40001 ) is not None, "40001 polled", **wfkw )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40001 ) == 0
    
        assert plc.read(     1 ) == None
        assert plc.read( 40002 ) == None
        success,elapsed		= waitfor( lambda: plc.read( 40002 ) is not None, "40002 polled", **wfkw )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40002 ) == 0
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


@pytest.mark.skipif( 'SERIAL_TEST' not in os.environ or not has_o_nonblock or not has_pymodbus or not has_pyserial,
                     reason="Needs SERIAL_TEST and fcntl/O_NONBLOCK and pymodbus and pyserial" )
def test_rs485_multi( simulated_modbus_rtu_ttyS0,  simulated_modbus_rtu_ttyS2 ):

    command,address		= simulated_modbus_rtu_ttyS0
    command,address		= simulated_modbus_rtu_ttyS2
    Defaults.Timeout		= PORT_TIMEOUT
    client			= modbus_client_rtu( framer=modbus_rtu_framer_collecting,
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE )

    # 4 poller_modbus instances sharing the same RTU Master 'client'.  They will all block on I/O
    # access via the same RS485 media interface.
    slaves			= [1,2,3,4]
    plc				= {}
    for unit in slaves:
        plc[unit]		= poller_modbus( "RS485 unit %s" % ( unit ), client=client, unit=unit, rate=.25 )

    wfkw			= dict( timeout=1.0, intervals=10 )

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

        # Haven't polled 1 or 40002 yet
        for unit in slaves:
            assert plc[unit].read(     1 ) == None
            assert plc[unit].read( 40002 ) == None
        for unit in slaves:
            success, elapsed	= waitfor( lambda: plc[unit].read( 40002 ) is not None, "%d/40002 polled" % ( unit ), **wfkw )
            assert success
            assert elapsed < 1.0
            assert plc[unit].read( 40002 ) == 0

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


@pytest.mark.skipif( 'SERIAL_TEST' not in os.environ or not has_pymodbus or not has_pyserial or not has_o_nonblock, 
                     reason="Needs SERIAL_TEST and pymodbus and pyserial and fcntl/O_NONBLOCK" )
def test_rs485_modbus_polls( simulated_modbus_rtu_ttyS0 ):
    Defaults.Timeout		= 1.0 # PLC simulator has .25s delay
    # Set a default poll rate of 1.0s for new registers, and a reach of 10.
    command,address		= simulated_modbus_rtu_ttyS0
    unit			= PORT_SLAVES[address][0] # pick one of the units on this simulator
    client			= modbus_client_rtu( framer=modbus_rtu_framer_collecting,
        port=PORT_MASTER, stopbits=PORT_STOPBITS, bytesize=PORT_BYTESIZE,
        parity=PORT_PARITY, baudrate=PORT_BAUDRATE )
    plc				= poller_modbus( "RS485 unit %s" % unit, client=client, unit=unit, reach=10, rate=1.0 )
    try:
        run_plc_modbus_polls( plc )
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
        waitfor( lambda: not plc.is_alive(), "RS485 unit %s done" % unit, timeout=1.0 )

