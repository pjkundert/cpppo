
import fcntl
import logging
import os
import signal
import subprocess
import time
import traceback

import pytest

from . import misc
from .remote import *


logging.basicConfig( level=logging.DEBUG,
                     format="%(asctime)s %(name)-20s %(levelname)-8s %(message)s" )


class nonblocking_command( object ):
    """Set up a non-blocking command producing output.  Read the output using:

        collect 		= ''
        while True:
            if command is None:
		# Restarts command on failure, for example
    		command 	= nonblocking_command( ... )

            try:
                data 		= command.stdout.read()
                logging.debug( "Received %d bytes from command, len( data ))
                collect        += data
            except IOError as exc:
                if exc.errno != errno.EAGAIN:
                    logging.warning( "I/O Error reading data: %s" % traceback.format_exc() )
                    command	= None
		# Data not presently available; ignore
            except:
                logging.warning( "Exception reading data: %s", traceback.format_exc() )
                command		= None

            # do other stuff in loop...

    The command is killed when it goes out of scope.
    """
    def __init__( self, command ):

        shell			= type( command ) is not list
        self.command		= ' '.join( command ) if not shell else command
        logging.info( "Starting command: %s", self.command )
        self.process		= subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid, shell=shell )

        fd 			= self.process.stdout.fileno()
        fl			= fcntl.fcntl( fd, fcntl.F_GETFL )
        fcntl.fcntl( fd, fcntl.F_SETFL, fl | os.O_NONBLOCK )

    @property
    def stdout( self ):
        return self.process.stdout

    def kill( self ):
        logging.info( 'Sending SIGTERM to PID [%d]: %s, from: %s', self.process.pid, self.command, traceback.format_stack())
        try:
            os.killpg( self.process.pid, signal.SIGTERM )
        except OSError as exc:
            logging.info( 'Failed to send SIGTERM to PID [%d]: %s', self.process.pid, exc )
        else:
            logging.info( "Waiting for command (PID [%d]) to terminate", self.process.pid )
            self.process.wait()

        logging.info("Command (PID [%d]) finished with status [%d]: %s", self.process.pid, self.process.returncode, self.command )

    __del__			= kill


@pytest.fixture(scope="module")
def simulated_modbus_plc():
    return nonblocking_command( [
        os.path.join( '.', 'bin', 'modbus-sim.py' ), 
        '--evil', 'delay:.25', 
        '--address', 'localhost:11502',
        '00001-01000=0',
        '40001-41000=0', ] )


has_pymodbus			= False
try:
    import pymodbus
    from pymodbus.constants import Defaults
    from pymodbus.exceptions import ModbusException
    from .remote import plc_modbus
    has_pymodbus		= True
except ImportError:
    pass


def test_pymodbus_version():
    if not has_pymodbus:
        return
    version			= tuple( int( i ) for i in pymodbus.__version__.split( '.' ))
    expects			= (1,2,0)
    assert version >= expects, "Version of pymodbus is too old: %r; expected %r or newer" % (
        version, expects )

def await( pred, what="predicate", delay=1.0, intervals=10 ):
    begun			= misc.timer()
    truth			= False
    for _ in range( intervals ):
        truth			= pred()
        if truth:
            break
        time.sleep( delay/intervals )
    now				= misc.timer()
    logging.info( "After %7.3f/%7.3f %s %s" % (
            now - begun, delay, "detected" if truth else "missed  ", what ))

def test_device():
    p				= plc.poller_simulator( "PLC 1", rate=.5 )
    m				= io.motor( "chest", "M1", "Pressure Motor 1",
                                         plc=p, auto=100001, running=100002, start=1, 
                                         fault=100003, reset=100004, estop=100005 )
    await( lambda: m.auto == 0, "m.auto polled")
    assert m.auto == 0
    assert m.start == 0
    m.start = True
    await( lambda: m.start == 1, "m.start = True" )
    assert m.start
    assert p.read( 1 ) == 1
    p.write( 100002, 1 )
    await( lambda: m.running == 1, "10002 <== 1" )
    assert m.running

def test_plc_merge():
    """ plc utility functions for merging/shattering Modbus address ranges """
    if not has_pymodbus:
        return
    assert list( plc_modbus.shatter( *(1,8), limit=3 )) == [(1,3), (4,3), (7,2) ]
    assert list( plc_modbus.merge( [ (1,2), (2,3) ] )) == [ (1,4) ]
    assert list( plc_modbus.merge( [ (1,2), (2,3), (6,6), (40001,5) ] )) == [ (1,4), (6,6), (40001,5) ]
    assert list( plc_modbus.merge( [ (1,2), (2,3), (6,6), (40001,5) ], reach=5 )) \
        == [ (1,11), (40001,5) ]
    assert list( plc_modbus.merge( [ (1,2), (2,3), (6,6), (40001,5) ], reach=5, limit=5 )) \
        == [ (1,5), (6,5), (11,1), (40001,5) ]
    # Test avoidance of merging different register types.
    assert list( plc_modbus.merge( [ (9998,1), (9999,1), (10000,1) ], reach=5, limit=5 )) \
        == [ (9998,2), (10000,1)]

def test_plc_modbus( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    Defaults.Timeout		= 1.0
    plc				= plc_modbus.poller_modbus( "Motor PLC", port=11502 )
    plc.write( 1, 1 )


def test_plc_modbus_timeouts( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    # Now, try one that will fail due to PLC I/O response timeout.  The PLC
    # should be configured to time out around 0.25s.
    plc				= plc_modbus.poller_modbus( "Motor PLC", port=11502 )
    deadline			= 0.25 # Configured on simulated PLC start-up (GNUmakefile)

    # Slowly increase the timeout 'til success, ranging from -20% to +20% of the
    # deadline.  Demands success after timeout exceeds deadline by 110%, failure
    # if timeout is lower than 90% of deadline.
    for factor in range( 70, 130, 5 ):
        Defaults.Timeout	= deadline * factor / 100
        logging.info( "Writing with timeout %7.3f (%d%% of deadline %7.3f)" % (
            Defaults.Timeout, factor, deadline ))
        try:
            plc.write( 1, 1 )
            # If the timeout is still pretty short, should have failed!
            assert Defaults.Timeout > deadline * 90 / 100, \
                "Write should have timed out; only %7.3fs provided of %7.3fs deadline" % (
                    Defaults.Timeout, deadline )
        except ModbusException as e:
            # The only acceptable failure is a timeout; but not if plenty of timeout provided!
            assert str( e ).find( "failed: Timeout" )
            logging.info( "Write transaction timed out (slow plc) as expected" )
            assert Defaults.Timeout < deadline * 110 / 100, \
                "Write should not have timed out; %7.3fs provided of %7.3fs deadline" % (
                    Defaults.Timeout, deadline )

    Defaults.Timeout		= 0.1
    plc_bad			= plc_modbus.poller_modbus( "Motor PLC", port=11503 )
    try:
        plc.write( 1, 1 )
        assert False, "Write should have failed due to connection failure after %7.3f seconds" % (
            Defaults.Timeout )
    except ModbusException as e:
        assert str( e ).find( "failed: Timeout" )
        logging.info( "Write transaction timed out (bad plc) as expected" )

def test_plc_modbus_polls( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    Defaults.Timeout		= 1.0
    plc				= plc_modbus.poller_modbus( "Motor PLC", port=11502 )
    # Initial conditions (in case PLC is persistent between tests)
    plc.write( 1, 0 )
    plc.write( 40001, 0 )

    try:
        plc.poll( 40001, rate=.5 )
    
        await( lambda: plc.read( 40001 ) is not None, "40001 polled" )
        assert plc.read( 40001 ) == 0
    
        assert plc.read( 1 ) == None
        assert plc.read( 40002 ) == None
        await( lambda: plc.read( 40002 ) is not None, "40002 polled" )
        await( lambda: plc.read( 1 ) is not None, "00001 polled" )
        assert plc.read( 1 ) == 0
        assert plc.read( 40001 ) == 0
    
        plc.write( 1, [1, 0, 1, 0, 0, 1, 0, 0, 0, 1 ])
        plc.write( 40002, 1 )
        await( lambda: plc.read( 40002 ) == 1, "40002 polled" )
        await( lambda: plc.read( 1 ) == 1, "00001 polled" )
        assert( plc.read( 40002 ) == 1 )
        assert( plc.read( 1 ) == 1 )
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
