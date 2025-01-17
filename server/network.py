
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

import contextlib
import errno
import functools
import json
import logging
import multiprocessing
import os
import re
import select
import socket
import sys
import signal
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
def recv( conn, maxlen=4*1024 ):
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
def recvfrom( conn, maxlen=4*1024 ):
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


class server_runner( object ):
    """A generic server handler runner.  Supply a handler taking an open socket connection to target=...
    Assumes at least one or two arg=(conn,[addr,[...]]), and a callable target with an __name__
    attribute.  The 'args' argument is required, and must contain at least the connect socket, and
    (optional) peer address; all other keyword options (eg. kwargs, ...) are passed along to
    eg. Thread/Process.

    The kwargs keyword argument is passed unmolested to Thread/Process, which in turn breaks it out as
    keyword arguments to the Threads/Process' target function.

    """
    def __init__( self, **kwds ):
        super( server_runner, self ).__init__( **kwds ) # something with a Thread/Process interface, probably...
        #self._name		= kwds['target'].__name__
        assert 'args' in kwds and 1 <= len( kwds['args'] ) <= 2, \
            "Expected target to be supplied args conn: <socket>, addr: ('host',port)"
        self.conn		= kwds['args'][0]
        self.addr	        = kwds['args'][1] if len( kwds['args'] ) > 1 else None
        log.info( "%s server TID [%5s/%5s] runner target %s", self.name,
                  os.getpid(), self.ident, kwds['target'].__name__ )

    def run( self ):
        log.info( "%s server TID [%5s/%5s] starting on %r", self.name,
                  os.getpid(), self.ident, self.addr )
        try:
            return super( server_runner, self ).run()
        except Exception as exc:
            log.warning( "%s server failure: %s\n%s", self.name,
                         exc, ''.join( traceback.format_exc() ))
        finally:
            log.info( "%s server TID [%5s/%5s] stopping on %r", self.name,
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
            return super( server_runner, self ).join( timeout=timeout )
        finally:
            if self.is_alive():
                # We must have timed out; server Thread hasn't responded to clean shutdown.  Override to
                # respond more aggressively.
                log.warning( "%s server TID [%5s/%5s] hanging on %r", self.name,  
                          os.getpid(), self.ident, self.addr )
            else:
                log.info( "%s server TID [%5s/%5s] complete on %r", self.name,
                          os.getpid(), self.ident, self.addr )


class server_process( server_runner, multiprocessing.Process ):
    def join( self, timeout=None ):
        """Caller is awaiting completion of this sub-process """
        return super( server_process, self ).join( timeout=timeout )

    def start( self, *args, **kwds ):
        """After we've started the '.run()' in a sub-process to serve the connection, we no longer have
        need of it here in the parent process.

        """
        try:
            return super( server_process, self ).start( *args, **kwds )
        except Exception as exc:
            log.warning( "%s server TID[%5s/%5s] failed starting sub-process to serve %r; %s",
                         os.getpid(), self.ident, self.addr, exc )
        else:
            log.info( "%s server TID[%5s/%5s] closing %r; now being served in sub-process",
                      os.getpid(), self.ident, self.addr )
            self.conn.close()


class server_thread( server_runner, threading.Thread ):
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


class server_profiler( object ):
    """Activates profiling on the server thread/process, and dumps profile stats (optionally) to the
    specified file, and summarizes to sys.stdout.

    """
    def __init__( self, filename=None, limit=50, **kwds ):
        """To maintain Python2/3 compatibility, we will allow no positional parameters to __init__

        """
        self.filename		= filename
        self.limit		= limit
        super( server_profiler, self ).__init__( **kwds )

    def run( self ):
        import cProfile, pstats
        profiler		= cProfile.Profile()
        profiler.enable()
        try:
            result		= super( server_profiler, self ).run()
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


class server_thread_profiling( server_profiler, server_thread ):
    pass


class server_process_profiling( server_profiler, server_process ):
    pass


def server_main(
        address,
        target		= None,
        kwargs		= None,
        idle_service	= None,
        thread_factory	= server_thread,
        reuse		= True,
        tcp		= True,
        udp		= False,
        address_output	= None,
        **kwds ):
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

    # Log the server's network i'face/port binding.  This is used by various tests/tools to
    # detect and use the server, so don't remove!
    log.normal( "%s server PID [%5d] starting on %r", name, os.getpid(), address )

    # Ensure that any server['control'] in kwds is a dict, {dot,api}dict or proxy.  Specifically, we
    # can handle an cpppo.apidict or cpppo.apidict_proxy via multiprocessing.Manager().apidict,
    # which responds to get/getattr by releasing the corresponding set/setdefault/setattr.  We will
    # respond to server['control']['done'] and ['disable'].  When this loop awakens it will sense
    # done/disable (without releasing the setattr, if an apidict was used!), and attempt to join the
    # server thread(s).  This will (usually) invoke a clean shutdown procedure.  Finally, after all
    # threads have been joined, the .disable/done will be released (via get) at top of loop
    if kwargs is None:
        kwargs			= {} # Thread can take None; Process requires a dict
    control			= kwargs.get( 'server', {} ).get( 'control', {} )
    if 'done' in control or 'disable' in control:
        log.normal( "{} server PID [{:5d}] responding to external done/disable signal via {!r} {!r}".format(
            name, os.getpid(), control.__class__, control ))

    # Establish some defaults for the server; done/disable False, .5s latency, 1s timeout.
    control['done']		= False
    control['disable']		= False
    if 'latency' not in control:
        control['latency']	= .5
    control['latency']		= float( control['latency'] )
    if 'timeout' not in control:
        control['timeout']	= 2 * control['latency']
    control['timeout']		= float( control['timeout'] )
    log.info( "Serving TCP/IP: {tcp:5}, UDP/IP: {udp:5}, w/ latency: {latency:7.3f}s, timeout: {timeout:7.3f}s {idle}".format(
            tcp=tcp, udp=udp, latency=control['latency'], timeout=control['timeout'],
            idle="(w/NO idle service)" if idle_service is None else "(with idle service)" ))

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
            log.warning( "Failed to start %s to service connection %r; %s",
                         thread_factory.__name__, addr, exc )
            conn.close()
            if thrd is not None:
                del thrd
            raise

    # Establish TCP/IP (listen) and/or UDP/IP (I/O) sockets (TCP first, in case someone is waiting to bind)
    if tcp:
        tcp_sock		= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        if reuse:
            tcp_sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 ) # Avoid delay on next bind due to TIME_WAIT
            if hasattr( socket, 'SO_REUSEPORT' ):
                tcp_sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEPORT, 1 )
        tcp_sock.bind( address )
        tcp_sock.listen( 100 ) # How may simultaneous unaccepted connection requests

        # Transmit the bound local i'face:port address to any interested parties.  This is done via
        # the control dict (for threading counterparties in the same Process, or multiprocessing
        # counterparties connecting via Manager().dict()), or via stdout for those listening to
        # output (eg. via subprocess.Popen)
        control['address']	= tcp_sock.getsockname()
        if address_output:
            print( "Network TCP Server address = {locl!r}".format( locl=control['address'] ))
            sys.stdout.flush()

    if udp:
        udp_sock		= socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        udp_sock.bind( address )
        control['address_udp']	= udp_sock.getsockname()
        if address_output:
            print( "Network UDP Server address = {locl!r}".format( locl=control['address_udp'] ))
            sys.stdout.flush()
        thread_start( udp_sock, None )

    # and report completion to external API (eg. web) via apidict by triggering get
    while ( not control.get( 'disable' ) and not control.get( 'done' )):
        started			= misc.timer()
        try:
            acceptable		= None
            if tcp:
                log.trace( "TCP/IP: Accepting for   {latency:7.3f}s".format( latency=control['latency'] ))
                acceptable	= accept( tcp_sock, timeout=control['latency'] )
            else:
                log.trace( "TCP/IP: Delaying for   {latency:7.3f}s".format( latency=control['latency'] ))
                time.sleep( control['latency'] ) # No TCP/IP; just pause
            duration		= misc.timer() - started
            if acceptable:
                conn,addr	= acceptable
                log.debug( "TCP/IP: Accepted after {duration:7.3f}s".format( duration=duration ))
                thread_start( conn, addr )
            elif idle_service is not None:
                log.debug( "TCP/IP: Idle Svc after {duration:7.3f}s".format( duration=duration ))
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


@readable()
def decodefrom( source, encoding, errors=None ):
    """Python2/3 have wildly different socket.makefile blocking and encoding capabilities.  Also,
    codecs cannot handle non-blocking sources, so discard empty but not EOF sources here.

    """
    binary		= source.read()
    if binary:
        return binary.decode( encoding, errors=errors ) 
    return ''


def soakable( command ):
    return hasattr( command, 'is_alive' ) and hasattr( command, 'stdout' ) and command.stdout


def soak( command, control=None, address_latency=None, address_re=None ):
    """Soak up output in a non-blocking fashion, passing it thru to logging.  Optionally harvest any

        TCP ... address = ...

    found on command.stdout into control['address'].  The command.stdout is collected into local
    variable 'data', and full lines are logged.

    The command.stdout stream is assumed to be in *binary* mode, and may be non-blocking.
    Therefore, the .read() may return None.

    """
    if address_latency is None:
        address_latency		= 0.1
    if address_re is None:
        address_re		= r"[Ss]tarted.*address =\s*(?P<address>.*)?"

    assert address_latency is None or control, \
        "Must supply a control dict to receive address"
    data			= ''

    log.normal( "Soaking {!r} stdout".format( command ))
    while command.is_alive() and not ( control and control.get( 'done', False )):
        raw			= decodefrom( command.stdout, encoding='utf-8', errors='backslashreplace' )
        if not raw:
            time.sleep( address_latency )
            continue
        assert isinstance( raw, misc.type_str_base ), \
            "Received non-encoded output from command.stdout {!r}: {!r}".format(
                command.stdout, raw )

        #log.normal( "Read {:5d} bytes (had {:5d} bytes) from {!r}: {!r}".format(
        #    len( raw ), len( info['data'] ), command.stdout, raw ))
        data		       += raw
        while data.find( '\n' ) >= 0:
            line,data		= data.split( '\n', 1 )
            log.detail( ">>> {}".format( line ))
            if address_re and not ( control and control.get( 'address' )):
                m		= re.search( address_re, line )
                if m:
                    address_str	= m.group('address').strip()
                    # May be IPv4Address,int|None if <addr> looks like an IP address, and no <port>
                    host,port	= misc.parse_ip_port( address_str )
                    log.normal( "*** Server address = {!r} ==> {!r}:{!r}".format( address_str, host, port ))
                    control['address'] = str(host),port
    log.normal( "Soaking {!r} done.".format( command ))


def bench(
        server_func,
        client_func,
        client_count,
        server_kwds		= None,
        client_kwds		= None,
        client_max		= 10,
        server_join_timeout	= 1.0,
        address_latency		= 0.1,
        address_delay		= None,   # soak up address/output iff address_delay > 0
        address_via_stdout	= False,  # optionally via stdout
        server_cls		= None ):

    """Bench-test the server_func (with optional keyword args from server_kwds) as a process; will fail
    if one already bound to port.  Creates a thread pool (default 10) of client_func.  Each client
    is supplied a unique number argument, and the supplied client_kwds as keywords, and should
    return Falsey (eg. 0, False) on success, Truthy (eg. True, !0) on failure.

    Both threading.Thread and multiprocessing.Process work fine for running a bench server.
    However, Thread needs to use the out-of-band means to force server_main termination (since we
    can't terminate a Thread).  This is implemented as a container (eg. dict-based cpppo.apidict)
    containing a done signal.

    NOTE:

    Any server Process that writes an "address = ..." to its stdout within address_delay seconds
    will get that address passed to the client as address=... keyword argument.

    """
    if server_kwds is None:
        server_kwds		= {}
    assert server_kwds.__class__ is dict, \
        "Must use a plain dict for server_kwds, as it is passed as kwds parameter to Thread/Process"

    # If an address is desired, we'll be transmitting that back via server['control'], so ensure
    # that we at least have a dict at that path.
    if address_delay:
        assert 'server' in server_kwds and 'control' in server_kwds['server'], \
            "Must provide a server_kwds['server']['control'] dict to receive server's address: {!r}".format(
                server_kwds
            )
    
    # Either multiprocessing.Process (default) or threading.Thread should work as the Server.
    if server_cls is None:
        server_cls		= multiprocessing.Process

    # For threading, since the server Thread is in the same process and has direct access to the
    # provided server_kwds.server.control... dict, it can directly write data (eg. address) to it.

    # For multiprocessing, the server['control'] dict must be multiprocessing.Manager().dict().
    # This will result in any change to the control['done'] and control['address'] signal passing
    # thru to/from the sub-process.

    # Only multiprocessing.pool.ThreadPool works, as we cannot serialize some client API objects
    from multiprocessing.pool	import ThreadPool as Pool
    #from multiprocessing.dummy	import Pool
    #from multiprocessing	import Pool

    log.normal( "Server %r startup...", misc.function_name( server_func ))

    log.detail( "Server {!r} keywords: {!r}".format( misc.function_name( server_func ), server_kwds ))
    server_args			= ()

    server_stdout		= None
    buffering			= None

    if address_delay and address_via_stdout:
        assert server_cls is multiprocessing.Process, \
            "Must use multiprocessing.Process when detecting server address via stdout"

        read_sock,write_sock	= socket.socketpair()	# two unix-domain sockets

        # Create a shim that redirects stdout for the started server Process
        class Server( server_cls ):
            _write_socket	= write_sock

            def run( self ):
                with misc.redirect_stdout(
                        misc.make_socket_stream(
                            self._write_socket, "w", buffering=buffering, encoding='utf-8' )):
                    return super( Server, self ).run()
        server_cls		= Server

        read_sock.setblocking( False )
        server_stdout		= misc.make_socket_stream( read_sock, "rb", buffering=buffering )
        log.normal( "Created receiving command.stdout: {!r}".format( server_stdout ))


    # Ready to fire up the server!  Its address will be harvested either via shared apidict (proxy,
    # if multiprocessing), or from server stdout.
    server			= server_cls(
        target	= server_func,
        args	= server_args,
        kwargs	= server_kwds or {},  # Must be a plain dict for this to work reliably
    )
    server.daemon		= True
    if server_stdout:
        server.stdout		= server_stdout
    server.start()
    begun			= misc.timer()

    if address_delay:
        # Wait for the address to be harvested, failing if not
        if address_via_stdout:
            # Harvest any "address = ..." from the Process' .stdout (if defined).  Also monitors the shared
            # server_kwds['control']['done'] to detect server exit condition.  Puts collected data
            # (eg. address, data) in server_kwds['soak'].
            assert soakable( server ), "Cannot soak address via stdout from server {!r}".format( server )
            soaker		= threading.Thread(
                target	= soak,
                args	= (),
                kwargs	= dict(
                    command		= server,
                    control		= server_kwds['server']['control'],
                    address_latency	= address_latency,
                )
            )
            soaker.daemon		= True
            soaker.start()
            while server_kwds['server']['control'].get( 'address' ) is None and misc.timer() - begun < address_delay:
                log.detail( "Current server_kwds.server.control: {!r} {}".format(
                    server_kwds['server']['control'].__class__.__name__,
                    server_kwds['server']['control'] )
                )
                time.sleep( address_latency )
            assert server_kwds['server']['control'].get( 'address' ), \
                "Failed to harvest address with in {}s".format( address_delay )
        else:
            # Wait for the control['address'] to show up via apidict
            while server_kwds.get( 'server', {} ).get( 'control', {} ).get( 'address' ) is None and misc.timer() - begun < address_delay:
                log.detail( "Current server_kwds.server.control: {!r} {}".format(
                    server_kwds['server']['control'].__class__.__name__,
                    server_kwds['server']['control'] )
                )
                time.sleep( address_latency )
        assert server_kwds.get( 'server', {} ).get( 'control', {} ).get( 'address' ), \
            "Failed to harvest address with in {}s".format( address_delay )
        log.detail( "Final server_kwds: {}".format( server_kwds ))

    log.detail( "Final server_kwds: {}".format( json.dumps( server_kwds, indent=4, default=str )))

    # If we harvested an "address = ...' (or were provided one), pass it to the client in client_kwds
    if address_delay:
        address			= server_kwds['server']['control']['address']
        if address:
            if client_kwds is None:
                client_kwds	= {}
            log.normal( "Server {!r} address = {!r}; passing to client(s)".format(
                server, address ))
            client_kwds['address'] = address

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
        # Shut down server; use 'server.control.done = True' to stop server, if available.  If this
        # doesn't work, terminate/kill the Server my increasingly lethal means, splitting the join
        # timeout between the available methods.
        if server_kwds and 'done' in server_kwds.get( 'server' ).get( 'control', {} ):
            log.detail( "Server %r done signalled", misc.function_name( server_func ))
            server_kwds['server']['control']['done'] = True	# only useful for threading.Thread; Process cannot see this
        if server.is_alive():
            server.join( timeout=server_join_timeout/2 )
        if server.is_alive():
            if hasattr( server, 'terminate' ): # only if using multiprocessing.Process(); Thread doesn't have
                log.normal( "Server %r done via .terminate()", misc.function_name( server_func ))
                server.terminate()
            elif hasattr( server, 'pid' ):
                log.normal( "Server %r done via SIGTERM", misc.function_name( server_func ))
                os.kill( server.pid, signal.SIGTERM )
        if server.is_alive():
            server.join( timeout=server_join_timeout/2 )
        if server.is_alive():
            if hasattr( server, 'kill' ):
                log.warning( "Server %r remains running; kill()...", misc.function_name( server_func ))
                server.kill()
            elif hasattr( server, 'pid' ):
                log.warning( "Server %r remains running; SIGKILL...", misc.function_name( server_func ))
                os.kill( server.pid, signal.SIGKILL )
        else:
            log.normal( "Server %r stopped.", misc.function_name( server_func ))
