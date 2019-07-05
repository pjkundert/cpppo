
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

import errno
import functools
import logging
import os
import select
import socket
import sys
import threading
import time
import traceback

from .. import misc
from ..dotdict import dotdict

log				= logging.getLogger( "network" )

def readable( timeout=0, default=None ):
    """Decorates any function( sock, ..., [timeout=...], [...]), and waits for its sock (must be the
    first positional arg) to report readable w/in timeout before executing.  Returns default (None)
    if not readable.  Supply the desired default timeout to the decorator if other than 0, or supply
    it as an optional keyword argument to the decorated function.

    """
    def decorator( function ):
        @functools.wraps( function )
        def wrapper( *args, **kwds ):
            tmo			= kwds.pop( 'timeout', timeout )
            beg			= misc.timer()
            rem			= tmo
            r			= None # In case select raises exception first time thru
            while True:
                try:
                    r,_,_	= select.select( [args[0].fileno()], [], [], rem )
                except select.error as exc:
                    if ( exc.args[0] if sys.version_info[0] < 3 else exc.errno ) == errno.EINTR:
                        # EINTR.  If the timeout has been exceeded, loop once with a zero timeout
                        # (to reliably detect EOF, in heavily loaded situations with lots of
                        # EINTRs).  Otherwise, recompute the remaining timeout.  In Python >= 3.5,
                        # PEP 475 does this automatically (we shouldn't see EINTR).
                        rem	= max( 0, beg + tmo - misc.timer() )
                        continue
                    raise		# Not select.error, or not EINTR
                break			# readable, or timeout expired
            return function( *args, **kwds ) if r else default
        return wrapper
    return decorator


@readable( default=None )
def recv( conn, maxlen=1024 ):
    """Non-blocking recv via. select, accepts optional timeout= keyword parameter.  Return None if no
    data received within timeout (default is immediate timeout).  Otherwise, the data payload; zero
    length data (or socket error) implies EOF.

    """
    try:
        msg			= conn.recv( maxlen ) # b'' (EOF) or b'<data>'
    except socket.error as exc: # No connection; same as EOF
        log.debug( "recv %s: %r", conn, exc )
        msg			= b''
    return msg


@readable( default=(None,None) )
def recvfrom( conn, maxlen=1024 ):
    """Non-blocking recvfrom via. select, accepts optional timeout= keyword parameter.  Return None if
    no data received within timeout (default is immediate timeout).  Otherwise, the data payload;
    zero length data implies EOF.

    """
    try:
        msg,frm			= conn.recvfrom( maxlen ) # b'' (EOF) or b'<data>'
    except socket.error as exc: # No connection; same as EOF
        log.debug( "recv %s: %r", conn, exc )
        msg,frm			= b'',None
    return msg,frm


@readable()
def accept( conn ):
    return conn.accept()


def drain( conn, timeout=.1, close=True ):
    """Send EOF, drain and (optionally) close connection cleanly, returning any data received.  Will
    immediately detect an incoming EOF on connection and close, otherwise waits timeout for incoming
    EOF; if exception, assumes that the connection is dead (same as EOF).

    """
    try:
        conn.shutdown( socket.SHUT_WR )
    except socket.error as exc: # No connection; same as EOF
        log.debug( "shutdown %s: %r", conn, exc )
        msg			= b''
    else:
        msg			= recv( conn, timeout=timeout )

    if close:
        try:
            conn.close()
        except socket.error as exc: # Already closed
            log.debug( "close %s: %r", conn, exc )
            pass

    return msg


class server_thread( threading.Thread ):
    """A generic server handler Thread.  Supply a handler taking an open socket connection to target=...
    Assumes at least one or two arg=(conn,[addr,[...]]), and a callable target with an __name__
    attribute.  The 'args' argument is required, and must contain at least the connect socket, and
    (optional) peer address; all other keyword options (eg. kwargs, ...) are passed along to Thread.

    The kwargs keyword argument is passed unmolested to Thread, which in turn breaks it out as
    keyword arguments to the Threads's target function."""
    def __init__( self, **kwds ):
        super( server_thread, self ).__init__( **kwds )
        self._name		= kwds['target'].__name__
        self.conn		= kwds['args'][0]
        self.addr	        = kwds['args'][1] if len( kwds['args'] ) > 1 else None

    def run( self ):
        log.info( "%s server TID [%5d/%5d] starting on %r", self._name,
                  os.getpid(), self.ident, self.addr )
        try:
            super( server_thread, self ).run()
        except Exception as exc:
            log.warning( "%s server failure: %s\n%s", self._name,
                         exc, ''.join( traceback.format_exc() ))
        log.info( "%s server TID [%5d/%5d] stopping on %r", self._name,
                  os.getpid(), self.ident, self.addr )

    def join( self, timeout=None ):
        """Caller is awaiting completion of this thread; try to shutdown (output) on the socket, which
        should (eventually) result in EOF on input and termination of the target service method.
        This procedure allows for a default "clean" shutdown of sockets on server termination.

        If clients are possibly misbehaving (eg. could be hung or the network could be arbitrarily
        delayed), supply a timeout and perform more aggressive shutdown/cleanup procedures on
        failure to stop cleanly.

        """
        try:
            self.conn.shutdown( socket.SHUT_WR )
        except:
            pass
        super( server_thread, self ).join( timeout=timeout )
        if self.is_alive():
            # We must have timed out; server Thread hasn't responded to clean shutdown.  Override to
            # respond more aggressively.
            log.warning( "%s server TID [%5d/%5d] hanging on %r", self._name,
                         os.getpid(), self.ident, self.addr )
        else:
            log.info( "%s server TID [%5d/%5d] complete on %r", self._name,
                      os.getpid(), self.ident, self.addr )


class server_thread_profiling( server_thread ):
    """Activates profiling on the thread, and dumps profile stats (optionally) to the specified file,
    and summarizes to sys.stdout.

    """
    def __init__( self, filename=None, limit=50, **kwds ):
        self.filename		= filename
        self.limit		= limit
        super( server_thread_profiling, self ).__init__( **kwds )

    def run( self ):
        import cProfile, pstats
        profiler		= cProfile.Profile()
        profiler.enable()
        try:
            result		= super( server_thread_profiling, self ).run()
        finally:
            profiler.disable()
            if self.filename:
                profiler.dump_stats( self.filename )
            prof		= pstats.Stats( profiler, stream=sys.stdout )

            print( "\n\nTIME:")
            prof.sort_stats(  'time' ).print_stats( self.limit )

            print( "\n\nCUMULATIVE:")
            prof.sort_stats(  'cumulative' ).print_stats( self.limit )
        return result


def server_main( address, target=None, kwargs=None, idle_service=None, thread_factory=server_thread,
                 reuse=True, tcp=True, udp=False, **kwds ):
    """A generic server main, binding to address (on TCP/IP but not UDP/IP by default), and serving
    each incoming connection with a separate thread_factory (server_thread by default, a
    threading.Thread) instance running the target function (or its overridden run method, if
    desired).  Each server must be passed two positional arguments in the 'args' keyword (the
    connect socket and the peer address), plus any keyword args required by the target function in
    the 'kwargs' keyword.  Any remaining keyword parameters are passed to the thread_factory
    (eg. for server_thread_profiling, a 'file' keyword might be appropriate )

    The kwargs (default: None) container is passed to each thread; it is *shared*, and each thread
    must treat its contents with appropriate care.  It can be used as a conduit to transmit
    changing configuration information to all running threads.  Pass keys with values that are
    mutable container objects (eg. dict, list), so that the original object is retained when the
    kwargs is broken out into arguments for the Thread's target function.

    If a 'server' keyword is passed, it is assumed to be a dict/dotdict/apidict contain the
    server's status and control attributes.  When either the 'done' or 'disable' entry is set to
    True, the server_main will attempt to terminate all existing server threads, close the
    listening socket and return.  If a KeyboardInterrupt or other Exception occurs, then
    server.control.done will be forced True.

    Thus, the caller can optionally pass the 'server' kwarg dict; the 'disable' entry will force
    the server_main to stop listening on the socket temporarily (for later resumption), and 'done'
    to signal (or respond to) a forced termination.

    An optional 'latency' and 'timeout' kwarg entries are recognized, and sets the accept timeout
    (default: .1s): the time between loops checking our control status, when no incoming
    connections are available, and the join timeout (default: latency) allowed for each thread to
    respond to the server being done/disabled.

    If supplied, the 'idle_service' function will be invoked whenever 'latency' passes without an
    incoming socket being accepted.

    To successfully handle UDP/IP sessions, the target must be able to handle an 'conn' that is a
    UDP/IP SOCK_DGRAM socket, and an 'addr' which is None (since the peer is not know, and is
    possibly different on each request.)

    """

    name			= target.__name__ if target else thread_factory.__name__
    threads			= {}
    log.normal( "%s server PID [%5d] running on %r", name, os.getpid(), address )
    # Ensure that any server.control in kwds is a dotdict.  Specifically, we can handle an
    # cpppo.apidict, which responds to getattr by releasing the corresponding setattr.  We will
    # respond to server.control.done and .disable.  When this loop awakens it will sense
    # done/disable (without releasing the setattr, if an apidict was used!), and attempt to join the
    # server thread(s).  This will (usually) invoke a clean shutdown procedure.  Finally, after all
    # threads have been joined, the .disable/done will be released (via getattr) at top of loop
    control			= kwargs.get( 'server', {} ).get( 'control', {} ) if kwargs else {}
    if isinstance( control, dotdict ):
        if 'done' in control or 'disable' in control:
            log.normal( "%s server PID [%5d] responding to external done/disable signal in object %s",
                        name, os.getpid(), id( control ))
    else:
        # It's a plain dict; force it into a dotdict, so we can use index/attr access
        control			= dotdict( control )
    control['done']		= False
    control['disable']		= False
    if 'latency' not in control:
        control['latency']	= .5
    control['latency']		= float( control['latency'] )
    if 'timeout' not in control:
        control['timeout']	= 2 * control.latency
    control['timeout']		= float( control['timeout'] )

    def thread_start( conn, addr ):
        """Start a thread_factory Thread instance to service the given I/O 'conn'.  The peer 'addr' is
        supplied (if known; None, otherwise).  If peer address is None, the service Thread may
        decide to take alternative actions to determine the Peer address (ie. use socket.recvfrom).

        """
        thrd			= None
        try:
            thrd		= thread_factory( target=target, args=(conn, addr), kwargs=kwargs,
                                                  **kwds )
            thrd.daemon 	= True
            thrd.start()
            threads[addr]	= thrd
        except Exception as exc:
            # Failed to setup or start service Thread for some reason!  Don't remember
            log.warning( "Failed to start Thread to service connection %r; %s", addr, exc )
            conn.close()
            del thrd

    # Establish TCP/IP (listen) and/or UDP/IP (I/O) sockets
    if udp:
        udp_sock		= socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        udp_sock.bind( address )
        thread_start( udp_sock, None )

    if tcp:
        tcp_sock		= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        if reuse:
            tcp_sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 ) # Avoid delay on next bind due to TIME_WAIT
            if hasattr( socket, 'SO_REUSEPORT' ):
                tcp_sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEPORT, 1 )
        tcp_sock.bind( address )
        tcp_sock.listen( 100 ) # How may simultaneous unaccepted connection requests

    while not control.disable and not control.done: # and report completion to external API (eg. web)
        try:
            acceptable		= None
            if tcp:
                acceptable	= accept( tcp_sock, timeout=control['latency'] )
            else:
                time.sleep( control['latency'] ) # No TCP/IP; just pause
            if acceptable:
                conn,addr	= acceptable
                thread_start( conn, addr )
            elif idle_service is not None:
                idle_service()
        except KeyboardInterrupt as exc:
            log.warning( "%s server termination: %r", name, exc )
            control['done']	= True
        except Exception as exc:
            log.warning( "%s server failure: %s\n%s", name,
                         exc, ''.join( traceback.format_exc() ))
            control['done']	= True
        finally:
            # Tidy up any dead threads (or all, if done/disable).  We detect done/disable here, but
            # do not report it (yet) to external API if an apidict is used.
            for addr in list( threads ):
                if control['disable'] or control['done'] or not threads[addr].is_alive():
                    threads[addr].join( timeout=control['timeout'] )
                    del threads[addr]
    if tcp:
        tcp_sock.close()
    log.normal( "%s server PID [%5d] shutting down (%s)", name, os.getpid(),
                "disabled" if control['disable'] else "done" if control['done'] else "unknown reason" )
    return 0


def bench( server_func, client_func, client_count,
           server_kwds=None, client_kwds=None, client_max=10, server_join_timeout=1.0 ):
    """Bench-test the server_func (with optional keyword args from server_kwds) as a process; will fail
    if one already bound to port.  Creates a thread pool (default 10) of client_func.  Each client
    is supplied a unique number argument, and the supplied client_kwds as keywords, and should
    return 0 on success, !0 on failure.

    Both threading.Thread and multiprocessing.Process work fine for running a bench server.
    However, Thread needs to use the out-of-band means to force server_main termination (since we
    can't terminate a Thread).  This is implemented as a container (eg. dict-based cpppo.apidict)
    containing a done signal.

    """

    # Either multiprocessing.Process or threading.Thread will work as Process for the Server
    from multiprocessing 	import Process
    #from threading 		import Thread as Process

    # Only multiprocessing.pool.ThreadPool works, as we cannot serialize some client API objects
    from multiprocessing.pool	import ThreadPool as Pool
    #from multiprocessing.dummy	import Pool
    #from multiprocessing	import Pool

    log.normal( "Server %r startup...", misc.function_name( server_func ))
    server			= Process( target=server_func, kwargs=server_kwds or {} )
    server.daemon		= True
    server.start()
    time.sleep( .25 )

    try:
        log.normal( "Client %r tests begin, over %d clients (up to %d simultaneously)",
                    misc.function_name( client_func ), client_count, client_max )
        pool			= Pool( processes=client_max )
        # Use list comprehension instead of generator, to force start of all asyncs!
        asyncs			= [ pool.apply_async( client_func, args=(i,), kwds=client_kwds or {} )
                                    for i in range( client_count )]
        log.normal( "Client %r started %d times in Pool; harvesting results",
                    misc.function_name( client_func ), client_count )

        successes		= 0
        for a in asyncs:
            try:
                result		= a.get()
                successes      += 1 if not result else 0
                if result:
                    log.warning( "Client failed w/ non-0 result: %s", result )
            except Exception as exc:
                log.exception( "Client failed w/ Exception: %s", exc )


        failures		= client_count - successes
        log.normal( "Client %r tests done: %d/%d succeeded (%d failures)", misc.function_name( client_func ),
                  successes, client_count, failures )
        return failures
    finally:
        # Shut down server; use 'server.control.done = true' to stop server, if
        # available in server_kwds.  If this doesn't work, we can try terminate
        control			= server_kwds.get( 'server', {} ).get( 'control', {} ) if server_kwds else {}
        if 'done' in control:
            log.normal( "Server %r done signalled", misc.function_name( server_func ))
            control['done']	= True	# only useful for threading.Thread; Process cannot see this
        if hasattr( server, 'terminate' ):
            log.normal( "Server %r done via .terminate()", misc.function_name( server_func ))
            server.terminate() 		# only if using multiprocessing.Process(); Thread doesn't have
        server.join( timeout=server_join_timeout )
        if server.is_alive():
            log.warning( "Server %r remains running...", misc.function_name( server_func ))
        else:
            log.normal( "Server %r stopped.", misc.function_name( server_func ))
