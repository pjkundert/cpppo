
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
__license__                     = "GNU General Public License, Version 3 (or later)"

import logging
import os
import socket
import select
import threading
import traceback

log				= logging.getLogger( "network" )

def readable( timeout=0 ):
    """Decorates any function( sock, ..., timeout=, [...]), and waits for its sock (must be the first
    positional arg) to report readable w/in timeout before executing.  Returns None if not readable.
    Supply the desired default timeout, if other than 0."""
    def decorator( function ):
        import functools
        @functools.wraps( function )
        def wrapper( *args, **kwds ):
            if 'timeout' in kwds:
                timeout			= kwds['timeout']
                del kwds['timeout']
            try:
                r, w, e		= select.select( [args[0].fileno()], [], [], timeout )
            except select.error as exc:
                log.debug( "select: %r", exc )
                if exc.arg[0] != errno.EINTR:
                    raise
            if r:
                return function( *args, **kwds )
            return None
        return wrapper
    return decorator
        

@readable()
def recv( conn, maxlen=1024 ):
    """Non-blocking recv via. select.  Return None if no data received within timeout (default is
    immediate timeout).  Otherwise, the data payload; zero length data implies EOF."""
    try:
        msg			= conn.recv( maxlen ) # b'' (EOF) or b'<data>'
    except socket.error as exc: # No connection; same as EOF
        log.debug( "recv %s: %r", conn, exc )
        msg			= b''
    return msg

@readable(timeout=0)
def accept( conn ):
    return conn.accept()


def drain( conn, timeout=.1 ):
    """Send EOF, drain and close connection cleanly, returning any data received.  Will immediately
    detect an incoming EOF on connection and close, otherwise waits timeout for incoming EOF; if
    exception, assumes that the connection is dead (same as EOF)."""
    try:
        conn.shutdown( socket.SHUT_WR )
    except socket.error as exc: # No connection; same as EOF
        log.debug( "shutdown %s: %r", conn, exc )
        msg			= b''
    else:
        msg			= recv( conn, timeout=timeout )

    try:
        conn.close()
    except socket.error as exc: # Already closed
        log.debug( "close %s: %r", conn, exc )
        pass

    return msg


class server_thread( threading.Thread ):
    """A generic server handler Thread.  Supply a handler taking an open socket connection to target=...
    Assumes at least one or two arg=(conn,[addr,[...]]), and a callable target with an __name__
    attribute."""
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
            log.warning( "%s server failure: %r\n%s", self._name,
                         exc, traceback.format_exc() )
        log.info( "%s server TID [%5d/%5d] stopping on %r", self._name,
                  os.getpid(), self.ident, self.addr )

    def join( self ):
        """Caller is awaiting completion of this thread; try to shutdown (output) on the socket, which
        should (eventually) result in EOF on input and termination of the target service method."""
        try:
            self.conn.shutdown( socket.SHUT_WR )
        except:
            pass
        result			= super( server_thread, self ).join()
        if not self.is_alive():
            log.info( "%s server TID [%5d/%5d] complete on %r", self._name,
                      os.getpid(), self.ident, self.addr )


def server_main( address, target ):
    """A generic server main, binding to address, and serving each incoming connection with a separate
    server_thread (threading.Thread) instance running target function."""
    sock			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 ) # Avoid delay on next bind due to TIME_WAIT
    sock.bind( address )
    sock.listen( 100 ) # How may simultaneous unaccepted connection requests

    name			= target.__name__
    threads			= {}
    log.info( "%s server PID [%5d] running on %r", name, os.getpid(), address )
    done			= False
    while not done:
        try:
            acceptable		= accept( sock, timeout=.1 )
            if acceptable:
                conn, addr	= acceptable
                threads[addr]	= server_thread( target=target, args=(conn, addr) )
                threads[addr].start()
        except KeyboardInterrupt as exc:
            log.warning( "%s server termination: %r", name, exc )
            done		= True
        except Exception as exc:
            log.warning( "%s server failure: %r\n%s", name,
                         exc, traceback.format_exc() )
            done		= True
        finally:
            # Tidy up any dead threads (or all, if done)
            for addr in list( threads ):
                if done or not threads[addr].is_alive():
                    threads[addr].join()
                    del threads[addr]

    sock.close()
    log.info( "%s server PID [%5d] shutting down", name, os.getpid() )
    return 0


def bench( server_func, client_func, client_count, client_kwds=None, client_max=None ):
    """Bench-test the server_func as a process; will fail if one already bound to port.  Creates a
    thread pool (default 10) of client_func.  Each client is supplied a unique number argument, and
    the supplied client_kwds as keywords, and should return 0 on success, !0 on failure."""

    from multiprocessing 	import Process
    from multiprocessing.pool	import ThreadPool as Pool
    import time
    import json

    log.info( "Server startup..." )
    server			= Process( target=server_func )
    server.start()
    time.sleep( .25 )

    try:
        log.info( "Client tests: %d", client_count )
        pool			= Pool( processes=client_max or 10 )
        asyncs			= ( pool.apply_async( client_func, args=(i,), kwds=client_kwds or {} )
                                    for i in range( client_count ))
        successes		= sum( not a.get() for a in asyncs )

        failures		= client_count - successes
        log.info( "Client tests done: %d/%d succeeded (%d failures)" % ( successes, client_count, failures ))
        return failures

    finally:
        server.terminate()
        server.join()
