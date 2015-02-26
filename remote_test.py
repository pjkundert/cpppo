
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

from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import errno
import logging
import os
import random
import re
import signal
import socket
import subprocess
import threading
import time
import traceback

has_o_nonblock			= False
try:
    import fcntl
    has_o_nonblock		= True
except Exception:
    logging.warning( "Failed to import fcntl; skipping simulated Modbus/TCP PLC tests" )

import pytest

import cpppo
from   cpppo.remote.plc import poller_simulator, PlcOffline
from   cpppo.remote.io	import motor

log				= logging.getLogger(__name__)

has_pymodbus			= False
try:
    import pymodbus
    from pymodbus.constants import Defaults
    from pymodbus.exceptions import ModbusException
    from remote.plc_modbus import poller_modbus, merge, shatter
    from remote.pymodbus_fixes import modbus_client_tcp, modbus_server_tcp
    has_pymodbus		= True
except Exception as exc:
    logging.warning( "Failed to import pymodbus module; skipping Modbus/TCP related tests; run 'pip install pymodbus'; %s",
                    traceback.format_exc() )

RTU_WAIT			= 2.0  # How long to wait for the simulator
RTU_LATENCY			= 0.05 # poll for command-line I/O response 


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
        logging.info( 'Sending SIGTERM to PID [%d]: %s', self.process.pid, self.command )
        try:
            os.killpg( self.process.pid, signal.SIGTERM )
        except OSError as exc:
            logging.info( 'Failed to send SIGTERM to PID [%d]: %s', self.process.pid, exc )
        else:
            logging.info( "Waiting for command (PID [%d]) to terminate", self.process.pid )
            self.process.wait()

        logging.info("Command (PID [%d]) finished with status [%d]: %s", self.process.pid, self.process.returncode, self.command )

    __del__			= kill


def start_modbus_simulator( options ):
    command			= nonblocking_command( [
        os.path.join( '.', 'bin', 'modbus_sim.py' ), 
    ] + list( options ))

    begun			= cpppo.timer()
    address			= None
    data			= ''
    while address is None and cpppo.timer() - begun < RTU_WAIT:
        # On Python2, socket will raise IOError/EAGAIN; on Python3 may return None 'til command started.
        try:
            raw			= command.stdout.read()
            logging.debug( "Socket received: %r", raw)
            if raw:
                data  	       += raw.decode( 'utf-8' )
        except IOError as exc:
            logging.debug( "Socket blocking...")
            assert exc.errno == errno.EAGAIN, "Expected only Non-blocking IOError"
        except Exception as exc:
            logging.warning("Socket read return Exception: %s", exc)
        if not data:
            time.sleep( RTU_LATENCY )
        while data.find( '\n' ) >= 0:
            line,data		= data.split('\n', 1)
            logging.info( "%s", line )
            m			= re.search( "address = (.*)", line )
            if m:
                try:
                    host,port	= m.group(1).split(':')
                    address	= host,int(port)
                    logging.normal( "Modbus/TCP Simulator started after %7.3fs on %s:%d",
                                    cpppo.timer() - begun, address[0], address[1] )
                except:
                    assert m.group(1).startswith( '/' )
                    address	= m.group(1)
                    logging.normal( "Modbus/RTU Simulator started after %7.3fs on %s",
                                    cpppo.timer() - begun, address )
                break
    return command,address



@pytest.fixture(scope="module")
def simulated_modbus_tcp():
    """Start a simulator over a range of ports; parse the port successfully bound."""
    return start_modbus_simulator( options=[
        '-vv', '--log', 'remote_test.modbus_sim.log.localhost:11502',
        '--evil', 'delay:.25', 
        '--address', 'localhost:11502',
        '--range', '10',
        '    1 -  1000 = 0',
        '40001 - 41000 = 0',
    ] )


def test_pymodbus_version():
    if not has_pymodbus:
        return
    version			= tuple( int( i ) for i in pymodbus.__version__.split( '.' ))
    expects			= (1,2,0)
    assert version >= expects, "Version of pymodbus is too old: %r; expected %r or newer" % (
        version, expects )


def test_pymodbus_service_actions():
    if not has_pymodbus:
        return
    address			= ("localhost", 11502)

    class modbus_actions( modbus_server_tcp ):

        counter			= 0

        def service_actions( self ):
            log.detail( "client/timeout" )
            self.counter       += 1

    server			= None
    while address[1] < 11600:
        try:
            server 		= modbus_actions( context=None, address=address )
            break
        except socket.error as exc:
            assert exc.errno == errno.EADDRINUSE, \
                "Unexpected socket error; only address in use allowed: %s" % exc
            address		= (address[0],address[1]+1)
        except Exception as exc:
            log.warning( "Failed to start modbus_actions on %r: %s; %s",
                        address, exc, traceback.format_exc() )
            break

    assert server is not None, "Couldn't start modbus_actions"
    log.normal( "Success starting modbus_actions on %r", address )

    def modbus_killer():
        log.detail( "killer started" )
        time.sleep( 2 )
        log.detail( "killer server.shutdown" )
        server.shutdown()
        log.detail( "killer done" )
    try:
        killer			= threading.Thread( target=modbus_killer )
        killer.start()

        server.serve_forever( poll_interval=0.5 )
        assert 3 <= server.counter <= 5, "modbus_actions.service_actions not triggered ~4 times"
    finally:
        killer.join()


def await( pred, what="predicate", delay=1.0, intervals=10 ):
    """Await the given predicate, returning: (success,elapsed)"""
    begun			= cpppo.timer()
    truth			= False
    for _ in range( intervals ):
        truth			= pred()
        if truth:
            break
        time.sleep( delay/intervals )
    now				= cpppo.timer()
    elapsed			= now - begun
    log.info( "After %7.3f/%7.3f %s %s" % (
        elapsed, delay, "detected" if truth else "missed  ", what ))
    return truth,elapsed

def test_device():
    p				= poller_simulator( "PLC 1", rate=.5 )
    m				= motor( "chest", "M1", "Pressure Motor 1",
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


def test_plc_modbus_basic( simulated_modbus_tcp ):
    if not has_pymodbus or not has_o_nonblock:
        return
    command,(iface,port)	= simulated_modbus_tcp
    Defaults.Timeout		= 1.0
    try:
        client			= modbus_client_tcp( host=iface, port=port )
        plc			= poller_modbus( "Motor PLC", client=client )
        plc.write( 1, 1 )
    except Exception:
        log.warning( "Modbus/TCP Failed: %s", traceback.format_exc() )
    finally:
        log.info( "Stopping plc polling" )
        if plc:
            plc.done		= True
            await( lambda: not plc.is_alive(), "Motor PLC poller done" )


def test_plc_modbus_timeouts( simulated_modbus_tcp ):
    if not has_pymodbus or not has_o_nonblock:
        return
    # Now, try one that will fail due to PLC I/O response timeout.  The PLC
    # should be configured to time out around 0.25s.
    command,(iface,port)	= simulated_modbus_tcp
    #client			= modbus_client_tcp( host=iface, port=port ) # try old host=... API instead
    plc				= poller_modbus( "Motor PLC", host=iface, port=port )
    deadline			= 0.25 # Configured on simulated PLC start-up (GNUmakefile)

    try:
        # Slowly increase the timeout 'til success, ranging from -20% to +20% of the
        # deadline.  Demands success after timeout exceeds deadline by 110%, failure
        # if timeout is lower than 90% of deadline.
        for factor in range( 70, 130, 5 ):
            Defaults.Timeout	= deadline * factor / 100
            try:
                plc.write( 1, 1 )
                # If the timeout is still pretty short, should have failed!
                log.info( "Writing with timeout %7.3f (%d%% of deadline %7.3f) succeeded" % (
                    Defaults.Timeout, factor, deadline ))
                assert Defaults.Timeout > deadline * 90 / 100, \
                    "Write should have timed out; only %7.3fs provided of %7.3fs deadline" % (
                        Defaults.Timeout, deadline )
            except ModbusException as exc:
                # The only acceptable failure is a timeout; but not if plenty of timeout provided!
                log.info( "Writing with timeout %7.3f (%d%% of deadline %7.3f) failed" % (
                    Defaults.Timeout, factor, deadline ))
                assert str( exc ).find( "failed: Timeout" )
                log.info( "Write transaction timed out (slow plc) as expected" )
                assert Defaults.Timeout < deadline * 110 / 100, \
                    "Write should not have timed out; %7.3fs provided of %7.3fs deadline" % (
                        Defaults.Timeout, deadline )
    finally:
        log.info( "Stopping plc polling" )
        plc.done		= True
        await( lambda: not plc.is_alive(), "Motor PLC poller done" )


def test_plc_modbus_nonexistent( simulated_modbus_tcp ):
    if not has_pymodbus or not has_o_nonblock:
        return
    Defaults.Timeout		= 1.5
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
        await( lambda: not plc_bad.is_alive(), "Motor PLC poller done" )


def test_plc_modbus_polls( simulated_modbus_tcp ):
    if not has_pymodbus or not has_o_nonblock:
        return
    Defaults.Timeout		= 1.0 # PLC simulator has .25s delay
    # Set a default poll rate of 1.0s for new registers, and a reach of 10.
    command,(iface,port)	= simulated_modbus_tcp
    client			= modbus_client_tcp( host=iface, port=port )
    plc				= poller_modbus( "Motor PLC", client=client, reach=10, rate=1.0 )
    # Initial conditions (in case PLC is persistent between tests)
    plc.write(     1, 0 )
    plc.write( 40001, 0 )

    try:
        plc.poll( 40001, rate=1.0 )
    
        success,elapsed		= await( lambda: plc.read( 40001 ) is not None, "40001 polled" )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40001 ) == 0
    
        assert plc.read(     1 ) == None
        assert plc.read( 40002 ) == None
        success, elapsed	= await( lambda: plc.read( 40002 ) is not None, "40002 polled" )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40002 ) == 0
        success,elapsed		= await( lambda: plc.read(     1 ) is not None, "00001 polled" )
        assert success
        assert elapsed < 1.0
        assert plc.read(     1 ) == 0

        # Now add a bunch of new stuff to poll, and ensure polling occurs.  As
        # we add registers the number of distinct poll ranges will increase, and
        # then decrease as we in-fill and the inter-register range drops below
        # the merge reach 10, allowing the polling to merge ranges.  Thus, keep
        # track of the number of registers added, and allow
        # 
        # avg. 
        # poll
        # time
        #  
        #   |
        #   |
        # 4s|         ..
        # 3s|        .  .
        # 2s|     ...    ...
        # 1s|.....          .......
        #  -+----------------------------------
        #   |  10  20  30  40   regs
        
        regs			= {}
        extent			= 100
        probes			= extent * 5 // plc.reach
        elapsed			= None
        rolling			= None
        rolling_factor		= 1.0/5	# Rolling average over last ~8 samples
        while len( regs ) <= probes:
            # Always select a previously unpolled register; however, it might
            # have already been in a merge range; if so, get its current value
            # so we mutate it (forcing it to be re-polled)
            base		= 40001 if random.randint( 0, 1 ) else 1
            r			= None
            while r is None or r in regs:
                r		= random.randint( base, base + extent )
            v			= plc.read( r )
            if v is not None:
                log.detail( "New reg %5d was polled due to reach=%d", r, plc.reach )
                regs[r]		= v
            regs[r]		= ( regs[r] ^ 1 if r in regs
                                    else random.randint( 0, 65535 ) if base > 40000
                                    else random.randint( 0, 1 ) )

            plc.write( r, regs[r] )
            plc.poll( r )
            if len( regs ) > probes/2:
                # skip to the good parts...

                success,elapsed	= await( lambda: plc.read( r ) == regs[r], "polled %5d == %5d" % ( r, regs[r] ),
                                         delay=5.0, intervals=5*10 )
                assert success

                rolling		= cpppo.exponential_moving_average( rolling, elapsed, rolling_factor )

            log.normal( "%3d/%3d regs: polled %3d ranges w/in %7.3fs. Polled %5d == %5d w/in %7.3fs: avg. %7.3fs (load %3.2f, %3.2f, %3.2f)",
                             len( regs ), probes, len( plc.polling ), plc.duration,
                             r, regs[r], elapsed or 0.0, rolling or 0.0, *[cpppo.nan if load is None else load for load in plc.load] )

        assert rolling < plc.rate, \
            "Rolling average poll cycle %7.3fs should have fallen below target poll rate %7.3fs" % ( rolling, plc.rate )

        for r,v in regs.items():
            assert plc.read( r ) == v
    finally:
        log.info( "Stopping plc polling" )
        plc.done		= True
        await( lambda: not plc.is_alive(), "Motor PLC poller done" )
