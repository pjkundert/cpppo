
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
import socket
import select

log				= logging.getLogger( "network" )

# Decorates any function( sock, ..., timeout=, [...]), and waits for its sock
# (must be the first positional arg) to report readable w/in timeout before
# executing.  Returns None if not readable.  Supply the desired default timeout,
# if other than 0.
def readable( timeout=0 ):
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
    """Non-blocking recv via. select.  Return None if no data received within
    timeout (default is immediate timeout).  Otherwise, the data payload; zero
    length data implies EOF."""
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
    """Send EOF, drain and close connection cleanly, returning any data
    received.  Will immediately detect an incoming EOF on connection and close,
    otherwise waits timeout for incoming EOF; if exception, assumes that the
    connection is dead (same as EOF)"""
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

