
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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import errno
import logging
import os
import random
import re
import time
import traceback

import pytest

import cpppo
from   cpppo		import misc
from   cpppo.remote.plc	import (poller, poller_simulator, PlcOffline)
from   cpppo.remote.io	import (motor)

logging.basicConfig( **cpppo.log_cfg )
logging.getLogger().setLevel( logging.ERROR )
has_pymodbus			= False
try:
    import pymodbus
    from pymodbus.constants import Defaults
    from pymodbus.exceptions import ModbusException
    from remote.plc_modbus import (poller_modbus, merge, shatter)
    has_pymodbus		= True
except ImportError:
    logging.warning( "Missing pymodbus; skipping Modbus/TCP related tests" )


@pytest.fixture(scope="module")
def simulated_modbus_plc():
    """Start a simulator over a range of ports; parse the port successfully bound."""
    command			= misc.nonblocking_command( [
        os.path.join( '.', 'bin', 'modbus_sim.py' ), 
        '-vvv', '--log', 'remote_test.modbus_sim.log',
        '--evil', 'delay:.25', 
        '--address', 'localhost:11502',
        '--range', '10',
        '00001-01000=0',
        '40001-41000=0', ] )

    begun			= misc.timer()
    iface			= ''
    port			= None
    data			= ''
    while port is None and misc.timer() - begun < 1.0:
        try:
            data       	       += command.stdout.read()
        except IOError as exc:
            assert exc.errno == errno.EAGAIN, "Expected only Non-blocking IOError"
            time.sleep( .1 )
        while data.find( '\n' ) >= 0:
            line,data		= data.split('\n', 1)
            m			= re.search( "address = ([^:]*):(\d*)", line )
            if m:
                iface,port	= m.group(1),int(m.group(2))
                logging.warning( "Modbus/TCP Simulator started after %7.3fs on %s:%s",
                                 misc.timer() - begun, iface, port )
                break
    return command,(iface,port)


def test_pymodbus_version():
    if not has_pymodbus:
        return
    version			= tuple( int( i ) for i in pymodbus.__version__.split( '.' ))
    expects			= (1,2,0)
    assert version >= expects, "Version of pymodbus is too old: %r; expected %r or newer" % (
        version, expects )


def await( pred, what="predicate", delay=1.0, intervals=10 ):
    """Await the given predicate, returning: (success,elapsed)"""
    begun			= misc.timer()
    truth			= False
    for _ in range( intervals ):
        truth			= pred()
        if truth:
            break
        time.sleep( delay/intervals )
    now				= misc.timer()
    elapsed			= now - begun
    logging.info( "After %7.3f/%7.3f %s %s" % (
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


def test_plc_modbus_basic( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    command,(iface,port)	= simulated_modbus_plc
    Defaults.Timeout		= 1.0
    try:
        plc			= poller_modbus( "Motor PLC", port=port )
        plc.write( 1, 1 )
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
        await( lambda: not plc.is_alive(), "Motor PLC poller done" )


def test_plc_modbus_timeouts( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    # Now, try one that will fail due to PLC I/O response timeout.  The PLC
    # should be configured to time out around 0.25s.
    command,(iface,port)	= simulated_modbus_plc
    plc				= poller_modbus( "Motor PLC", port=port )
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
                logging.info( "Writing with timeout %7.3f (%d%% of deadline %7.3f) succeeded" % (
                    Defaults.Timeout, factor, deadline ))
                assert Defaults.Timeout > deadline * 90 / 100, \
                    "Write should have timed out; only %7.3fs provided of %7.3fs deadline" % (
                        Defaults.Timeout, deadline )
            except ModbusException as exc:
                # The only acceptable failure is a timeout; but not if plenty of timeout provided!
                logging.info( "Writing with timeout %7.3f (%d%% of deadline %7.3f) failed" % (
                    Defaults.Timeout, factor, deadline ))
                assert str( exc ).find( "failed: Timeout" )
                logging.info( "Write transaction timed out (slow plc) as expected" )
                assert Defaults.Timeout < deadline * 110 / 100, \
                    "Write should not have timed out; %7.3fs provided of %7.3fs deadline" % (
                        Defaults.Timeout, deadline )
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
        await( lambda: not plc.is_alive(), "Motor PLC poller done" )


def test_plc_modbus_nonexistent( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    Defaults.Timeout		= 0.1
    command,(iface,port)	= simulated_modbus_plc
    plc_bad			= poller_modbus( "Motor PLC", port=port+1) # Wrong port
    try:
        plc_bad.write( 1, 1 )
        assert False, "Write should have failed due to connection failure after %7.3f seconds" % (
            Defaults.Timeout )
    except PlcOffline as exc:
        logging.info( "Write transaction timed out (bad plc) as expected: %s", exc )
        assert str( exc ).find( "failed: Offline" )
    finally:
        logging.info( "Stopping plc polling" )
        plc_bad.done		= True
        await( lambda: not plc_bad.is_alive(), "Motor PLC poller done" )


def test_plc_modbus_polls( simulated_modbus_plc ):
    if not has_pymodbus:
        return
    Defaults.Timeout		= 1.0 # PLC simulator has .25s delay
    # Set a default poll rate of 1.0s for new registers, and a reach of 10.
    command,(iface,port)	= simulated_modbus_plc
    plc				= poller_modbus( "Motor PLC", reach=10, rate=1.0, port=port )
    # Initial conditions (in case PLC is persistent between tests)
    plc.write( 1, 0 )
    plc.write( 40001, 0 )

    try:
        plc.poll( 40001, rate=1.0 )
    
        success,elapsed		= await( lambda: plc.read( 40001 ) is not None, "40001 polled" )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40001 ) == 0
    
        assert plc.read( 1 ) == None
        assert plc.read( 40002 ) == None
        success, elapsed	= await( lambda: plc.read( 40002 ) is not None, "40002 polled" )
        assert success
        assert elapsed < 1.0
        assert plc.read( 1 ) == 0
        success,elapsed		= await( lambda: plc.read( 1 ) is not None, "00001 polled" )
        assert success
        assert elapsed < 1.0
        assert plc.read( 40001 ) == 0

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
        probes			= extent * 5 / plc.reach
        rolling			= None
        rolling_factor		= 1.0/5	# Rolling average over last ~5 samples
        while len( regs ) <= probes:
            if random.randint( 0, 1 ):
                r		= random.randint( 00001, 00001 + extent )
                v		= plc.read( r )
                if v is not None:
                    if r not in regs:
                        logging.warning( "New reg %5d was polled due to reach=%d", r, plc.reach )
                    regs[r]	= v
                regs[r]		= regs[r] ^ 1 if r in regs else random.randint( 0, 1 )
            else:
                r		= random.randint( 40001, 40001 + extent )
                v		= plc.read( r )
                if v is not None:
                    if r not in regs:
                        logging.warning( "New reg %5d was polled due to reach=%d", r, plc.reach )
                    regs[r]	= v
                regs[r]		= regs[r] ^ 1 if r in regs else 1

            plc.write( r, regs[r] )
            plc.poll( r )
            success,elapsed	= await( lambda: plc.read( r ) == regs[r], "polled %5d == %5d" % ( r, regs[r] ),
                                         delay=5.0, intervals=5*10 )
            assert success

            rolling		= elapsed if rolling is None else rolling * ( 1.0 - rolling_factor ) + elapsed * rolling_factor

            logging.warning( "%3d/%3d regs: Polled %5d == %5d w/in %7.3fs: avg. %7.3fs",
                             len( regs ), probes, r, regs[r], elapsed, rolling )

        assert rolling < plc.rate, \
            "Rolling average poll cycle %7.3fs should have fallen below target poll rate %7.3fs" % ( rolling, plc.rate )

        for r,v in regs.items():
            assert plc.read( r ) == v
    finally:
        logging.info( "Stopping plc polling" )
        plc.done		= True
        await( lambda: not plc.is_alive(), "Motor PLC poller done" )
