from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import errno
import logging
import os
import random
import re
import signal
import subprocess
import time

has_o_nonblock			= False
try:
    import fcntl
    has_o_nonblock		= True
except Exception:
    logging.warning( "Failed to import fcntl; skipping simulated Modbus/TCP PLC tests" )

from . import misc
from .tools.waits import waitfor

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
    command                     = nonblocking_command( [
        'python',
        os.path.join( os.path.dirname( os.path.abspath( __file__ )), 'bin', 'modbus_sim.py' ),
    ] + list( options ))

    begun			= misc.timer()
    address			= None
    data			= ''
    while address is None and misc.timer() - begun < RTU_WAIT:
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
            line,data		= data.split( '\n', 1 )
            logging.info( "%s", line )
            m			= re.search( "address = (.*)", line )
            if m:
                try:
                    host,port	= m.group(1).split( ':' )
                    address	= host,int(port)
                    logging.normal( "Modbus/TCP Simulator started after %7.3fs on %s:%d",
                                    misc.timer() - begun, address[0], address[1] )
                except:
                    assert m.group(1).startswith( '/' )
                    address	= m.group(1)
                    logging.normal( "Modbus/RTU Simulator started after %7.3fs on %s",
                                    misc.timer() - begun, address )
                break
    return command,address


def run_plc_modbus_polls( plc ):
    # Initial conditions (in case PLC is persistent between tests)
    plc.write(     1, 0 )
    plc.write( 40001, 0 )

    rate			= 1.0
    timeout			= 2 * rate 	# Nyquist
    intervals			= timeout / .05	#  w/ fixed .05s intervals
    wfkw			= dict( timeout=timeout, intervals=intervals )

    plc.poll( 40001, rate=rate )
    
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

    # Now add a bunch of new stuff to poll, and ensure polling occurs.  As we add registers the
    # number of distinct poll ranges will increase, and then decrease as we in-fill and the
    # inter-register range drops below the merge reach 10, allowing the polling to merge ranges.
    # Thus, keep track of the number of registers added, and allow
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

    # We'll be overwhelming the poller, so it won't be able to poll w/in the target rate, so we'll
    # need to more than double the Nyquist-rate timeout
    wfkw['timeout']	       *= 2.5
    wfkw['intervals']	       *= 2.5
    
    regs			= {}
    extent			= 100 # how many each of coil/holding registers
    total			= extent*2 # total registers in play
    elapsed			= None
    rolling			= None
    rolling_factor		= 1.0/5	# Rolling exponential moving average over last ~8 samples

    # Keep increasing the number of registers polled, up to 1/2 of all registers
    while len( regs ) < total * 50 // 100:
        # Always select a previously unpolled register; however, it might
        # have already been in a merge range; if so, get its current value
        # so we mutate it (forcing it to be re-polled)
        base			= 40001 if random.randint( 0, 1 ) else 1
        r			= None
        while r is None or r in regs:
            r			= random.randint( base, base + extent )
        v			= plc.read( r )
        if v is not None:
            logging.detail( "New reg %5d was already polled due to reach=%d", r, plc.reach )
            regs[r]		= v
        regs[r]			= ( regs[r] ^ 1 if r in regs
                                else random.randint( 0, 65535 ) if base > 40000
                                else random.randint( 0, 1 ) )

        plc.write( r, regs[r] )
        plc.poll( r )
        if len( regs ) > total * 10 // 100:
            # skip to the good parts...  After 10% of all registers are being polled, start
            # calculating.  See how long it takes, on average, to get the newly written register
            # value polled back.
            success,elapsed	= waitfor( lambda: plc.read( r ) == regs[r], "polled %5d == %5d" % ( r, regs[r] ), **wfkw )
            assert success
            rolling		= misc.exponential_moving_average( rolling, elapsed, rolling_factor )

        logging.normal( "%3d/%3d regs: polled %3d ranges w/in %7.3fs. Polled %5d == %5d w/in %7.3fs: avg. %7.3fs (load %3.2f, %3.2f, %3.2f)",
                         len( regs ), total, len( plc.polling ), plc.duration,
                         r, regs[r], elapsed or 0.0, rolling or 0.0, *[misc.nan if load is None else load for load in plc.load] )

        if len( regs ) > total * 20 // 100:
            # after 20%, start looking for the exit (ranges should merge, poll rate fall )
            if rolling < plc.rate:
                break

    assert rolling < plc.rate, \
        "Rolling average poll cycle %7.3fs should have fallen below target poll rate %7.3fs" % ( rolling, plc.rate )

    for r,v in regs.items():
        assert plc.read( r ) == v
