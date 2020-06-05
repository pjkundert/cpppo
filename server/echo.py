#! /usr/bin/env python

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


"""
echo	-- Implementation of UNIX "echo" server

USAGE
    python -m cpppo.server.echo

"""

import logging
import sys

import cpppo
from   cpppo.server import network

address				= ('', 8007)

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )
    #logging.getLogger().setLevel( logging.DEBUG )

log				= logging.getLogger( "echo.srv" )


class echo_regex( cpppo.regex_bytes_promote ):
    """Collects a line of bytes data out of our regex dfa's state_input data at path.context.input, and
    into data artifact at path.context (default is 'echo').  We want to terminate immediately on
    detection of end-of-line, so specify non-greedy."""
    def __init__( self, name=None, initial='.*\n', context="echo", greedy=False, **kwds ):
        super( echo_regex, self ).__init__(
            name=name, initial=initial, context=context, greedy=greedy, **kwds )


def echo_machine( name=None ):
    """Accept a full line of input bytes matching the given regular expression.
    Sub-machine terminates at earliest match (non-greedy), causing echo.transition to trigger
    .process (which resets our sub-machine to initial state), and then we move to the next state
    (loops), allowing us to immediately run."""
    machine			= echo_regex( name=name, terminal=True )
    return machine


def echo_server( conn, addr ):
    """Serve one echo client 'til EOF; then close the socket"""
    source			= cpppo.chainable()
    with echo_machine( "echo_%s" % addr[1] ) as echo_line:
        eof			= False
        while not eof:
            data		= cpppo.dotdict()
            # See if a line has been recognized, stopping at terminal state.  If this machine
            # is ended early due to an EOF, it should still terminate in a terminal state
            for mch, sta in echo_line.run( source=source, data=data ):
                if sta is not None:
                    continue
                # Non-transition; check for input, blocking if non-terminal and none left.  On
                # EOF, terminate early; this will raise a GeneratorExit.
                timeout		= 0 if echo_line.terminal or source.peek() is not None else None
                msg		= network.recv( conn, timeout=timeout )
                if msg is not None:
                    eof		= not len( msg )
                    log.info( "%s recv: %5d: %s", echo_line.name_centered(), len( msg ),
                              "EOF" if eof else cpppo.reprlib.repr( msg ))
                    source.chain( msg )
                    if eof:
                        break
            # Terminal state (or EOF).
            log.detail( "%s: byte %5d: data: %r", echo_line.name_centered(), source.sent, data )
            if echo_line.terminal:
                conn.send( data.echo )
        
        log.info( "%s done", echo_line.name_centered() )

def main():
    return network.server_main( address=address, target=echo_server )


if __name__ == "__main__":
    sys.exit( main() )
