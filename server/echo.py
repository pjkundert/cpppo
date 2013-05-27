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
    python -m cpppo.server.echo

"""

import errno
import logging
import os
import sys
import threading
import time
import traceback
try:
    import reprlib
except ImportError:
    import repr as reprlib

import cpppo
from   cpppo import misc
import cpppo.server
from   cpppo.server import network

address				= ('0.0.0.0', 8007)

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "echo.srv" )

class echo_regex( cpppo.regex_bytes_input ):
    """Collects a line of bytes data out of our regex dfa's state_input data at path.context.input, and
    into data artifact at path.context (default is 'echo')."""
    def __init__( self, name=None, initial='.*\n', context="echo", **kwds ):
        super( echo_regex, self ).__init__( name=name, initial=initial, context=context, **kwds )


def echo_machine( name=None ):
    """Accept a line of input bytes matching the given regular expression, and then
    loop.  Sub-machine terminates at earliest match (non-greedy), causing
    echo.transition to trigger .process (which resets our sub-machine to initial
    state), and then we move to the next state (loops), allowing us to
    immediately run."""
    machine			= echo_regex( name=name )
    return machine


def echo_server( conn, addr ):
    """Serve one echo client 'til EOF; then close the socket"""
    source			= cpppo.chainable()
    with echo_machine( "echo_%s" % addr[1] ) as echo_line:
        data			= cpppo.dotdict()
        sequence		= echo_line.run( source=source, data=data, greedy=False )
        while True:
            msg			= network.recv( conn, timeout=None ) # blocking
            log.info( "%s recv: %5d: %s", misc.centeraxis( echo_line, 25, clip=True ), 
                      len( msg ), reprlib.repr( msg ) if msg else "EOF" )
            if not msg: # None or empty
                break
            source.chain( msg )
        
            # See if a line has been recognized, stopping at terminal state
            for mch, sta in sequence:
                if sta is None:
                    break # No more transitions available on source input, but not terminal
            if sta:
                # Terminal state.  Echo, and reset to recognize the next new line of input
                log.info( "%s: data: %r", misc.centeraxis( echo_line, 25, clip=True ), data )
                conn.send( data.echo )
                echo_line.reset()
                data		= cpppo.dotdict()
                sequence	= echo_line.run( source=source, data=data, greedy=False )
            else:
                # Out of input, no complete line of echo input acquired.  Wait for more.
                log.debug( "%s: end of input", misc.centeraxis( echo_line, 25, clip=True ))
        
        log.info( "%s done: %s" % ( misc.centeraxis( echo_line, 25, clip=True ), reprlib.repr( data )))


def main():
    return network.server_main( address, echo_server )


if __name__ == "__main__":
    sys.exit( main() )
