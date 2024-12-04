from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import atexit
import errno
import logging
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
import traceback

log				= logging.getLogger( 'mbs_test' )

has_o_nonblock			= False
try:
    import fcntl
    has_o_nonblock		= True
except Exception:
    log.warning( "Failed to import fcntl; skipping simulated Modbus/TCP PLC tests" )

from . import misc
from .server.network import soak
from .dotdict import dotdict
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
                log.debug( "Received %d bytes from command, len( data ))
                collect        += data
            except IOError as exc:
                if exc.errno != errno.EAGAIN:
                    log.warning( "I/O Error reading data: %s" % traceback.format_exc() )
                    command	= None
                # Data not presently available; ignore
            except:
                log.warning( "Exception reading data: %s", traceback.format_exc() )
                command		= None

            # do other stuff in loop...

    The command is killed when it goes out of scope.  Pass a file-like object for stderr if desired;
    None would cause it to share the enclosing interpreter's stderr.

    As a safety mechanism, arrange to use atexit.register to terminate the command (if it isn't
    already dead).

    """
    def __init__( self, command, stderr=subprocess.STDOUT, stdin=None, bufsize=0, blocking=None ):
        shell			= type( command ) is not list
        self.command		= ' '.join( command ) if not shell else command
        log.info( "Starting command: %s", self.command )
        if sys.version_info[0] < 3:
            # Python2 assumes plain ASCII encoding (just passes through the raw data)
            self.process		= subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=stderr, stdin=stdin,
                bufsize=bufsize, preexec_fn=os.setsid, shell=shell )
        else:
            # Python3 supports encoding, so specify encoding='utf-8' support?  No, we must retain
            # binary data from the target process and decode it as received.  This retains
            # consistency with Python2, and also is necessary to support non-blocking sockets --
            # which defeat the built-in Python codecs, which do *not* offer non-blocking support.
            self.process		= subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=stderr, stdin=stdin,
                bufsize=bufsize, preexec_fn=os.setsid, shell=shell )
        log.normal( 'Started Server PID [%d]: %s', self.process.pid, self.command )
        if not blocking:
            self.non_blocking()
        # Really, really ensure we get terminated
        atexit.register( self.kill )

    def non_blocking( self ):
        fd 			= self.process.stdout.fileno()
        fl			= fcntl.fcntl( fd, fcntl.F_GETFL )
        fcntl.fcntl( fd, fcntl.F_SETFL, fl | os.O_NONBLOCK )

    @property
    def stdout( self ):
        return self.process.stdout

    def is_alive( self ):
        if hasattr( self.process, 'is_alive' ):
            return self.process.is_alive()
        return self.poll() is None

    # Return returncode on self.process exit, None if self.process is still running.
    def poll( self ):
        return self.process.poll()

    def wait( self, timeout=None ):
        if sys.version_info[0] < 3: # Python 2.x subprocess.Popen.wait() has no timeout...
            if timeout is not None:
                deadline = misc.timer() + timeout
                while self.poll() is None and misc.timer() < deadline:
                    time.sleep( min( timeout / 10, 0.1 ))
            return self.process.wait()
        return self.process.wait( timeout=timeout )

    def kill( self, timeout=None ):
        if self.is_alive():
            log.normal( 'Sending SIGTERM to PID [%d]: %s, via: %s', self.process.pid, self.command,
                            ''.join( traceback.format_stack() ) if log.isEnabledFor( logging.DEBUG ) else '' )
            try:
                self.process.terminate()
            except OSError: # Python2.7 doesn't check/ignore problems sending signals to already-dead processes
                pass
            if self.wait( timeout=timeout ) is None:
                log.normal( 'Sending SIGKILL to PID [%d]: %s', self.process.pid, self.command )
                try:
                    self.process.kill()
                except OSError:
                    pass
                self.process.wait()
        log.info( "Command (PID [%d]) finished with status %r: %s",
                      self.process.pid, self.process.returncode, self.command )

    __del__			= kill


def start_simulator( simulator, *options, **kwds ):
    """Start a simple EtherNet/IP CIP simulator (execute this file as __main__), optionally with
    Tag=<type>[<size>] (or other) positional arguments appended to the command-line.  Return the
    command-line used, and the detected (host,port) address bound.  Looks for something like:

        11-11 11:46:16.301     7fff7a619000 network  NORMAL   server_mai enip_srv server PID [ 7573] running on ('', 44818)

    containing a repr of the (<host>,<port>) tuple.  Recover this address using the safe
    ast.literal_eval.  Use the -A to provide this on stdout, or just -v if stderr is redirected to
    stdout (the default, w/o a stderr parameter to nonblocking_command)

    At least one positional parameter containing a Tag=<type>[<size>] must be provided.

    Note that the output of this file's interpreter is not *unbuffered* (above), so we can receive
    and parse the 'running on ...'!  We assume that server/network.py flushes stdout when printing
    the bindings.  We could use #!/usr/bin/env -S python3 -u instead to have all output unbuffered.


    The address soaked/harvested from the output of the simulator will be an (<interface>,<port>)
    tuple; the <interface> may be either a str, or an IPv[46]Address (convertible to a str).

    """
    command_list		= [ sys.executable, simulator, ] + list( options )

    # For python 2/3 compatibility (can't mix positional wildcard, keyword parameters in Python 2)
    address_wait		= kwds.pop( 'CMD_WAIT', 1.0 )
    address_latency		= kwds.pop( 'CMD_LATENCY', 0.1 )
    address_re			= kwds.pop( 'RE_ADDRESS', None )

    command                     = nonblocking_command( command_list, **kwds )

    begun			= misc.timer()

    control			= dotdict( address=None )
    soaker			= threading.Thread(
        target	= soak,
        args	= (),
        kwargs	= dict(
            command		= command,
            control		= control,
            address_latency	= address_latency,
            address_re		= address_re,
        ))
    soaker.daemon		= True
    soaker.start()
    while control.address is None and misc.timer() - begun < address_wait:
        time.sleep( address_latency )

    assert control.address, "Failed to harvest Simulator IP address"

    logging.normal( "Simulator started after %7.3fs on %s",
                    misc.timer() - begun, ':'.join( map( repr, control.address )))
    return command,control.address


def start_modbus_simulator( *options ):
    """Start bin/modbus_sim.py; assumes it flushes stdout when printing bindings so we can parse it
    here.

    """
    return start_simulator(
        os.path.join( os.path.dirname( os.path.abspath( __file__ )), 'bin', 'modbus_sim.py' ),
        *options
    )


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
            log.detail( "New reg %5d was already polled due to reach=%d", r, plc.reach )
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

        log.normal( "%3d/%3d regs: polled %3d ranges w/in %7.3fs. Polled %5d == %5d w/in %7.3fs: avg. %7.3fs (load %3.2f, %3.2f, %3.2f)",
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
