#! /usr/bin/env python3

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


"""
echo	-- Implementation of UNIX "echo" server

USAGE
    python -m cpppo.client.echo

"""

import logging
import os
import select
import socket
import sys
import time

try:
    from reprlib import repr as repr
except ImportException:
    from repr import repr as repr

import cpppo
import cpppo.greenery


logging.basicConfig( level=logging.INFO, datefmt='%m-%d %H:%M'  ,
    format='%(asctime)s.%(msecs)3.3s %(name)-6.6s %(levelname)-6.6s %(funcName)-10.10s %(message)s' )
_log				= logging.getLogger()

class echo( cpppo.dfa ):
    def __init__( self, name, address=('0.0.0.0',7), **kwds ):
        super( cpppo.dfa, self ).__init__( name, **kwds )

def serve( sock ):
    print( "%s.echo" % ( __package__ ))
    #print( "%s" % "\n".join( "%s: %r" % ( k, v ) for k,v in globals().items() ))
    while True:
        conn, addr 		= sock.accept()
        source			= cpppo.chainable()
        _log.info( "accept" )
        try:
            while True:
                try:
                    r, w, e	= select.select( [conn.fileno()], [], [conn.fileno()] )
                except select.error as e:
                    if e.arg[0] != errno.EINTR:
                        break
                if r:
                    mesg	= conn.recv( 1024 )
                    if len(mesg) == 0:
                        _log.info( "EOF" )
                        break
                    source.chain( mesg )
                    _log.info( cpppo.lazystr( lambda: "recv: %5d bytes: %s" % ( len( mesg ), repr( mesg ))))
                if e:
                    _log.warning( "Exceptional Condition: %r", e )
        finally:
            # Drain and close connection cleanly
            conn.shutdown( socket.SHUT_WR )
            time.sleep(.1)
            r, w, e		= select.select( [conn.fileno()], [], [], 0 )
            if r:
                conn.recv( 1024 )
            conn.close()

def main():
    address			= ( '0.0.0.0', 8007 )
    sock			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    sock.bind( address )
    sock.listen( 1 )
    _log.info("echo client running on %r", address )
    try:
        serve( sock )
    finally:
        sock.close()

if __name__ == "__main__":
    sys.exit(main())
