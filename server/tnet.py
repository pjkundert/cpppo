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
tnet		-- A server accepting tnetstrings

USAGE
    python -m cpppo.server.tnet

BACKGROUND

    The grammar for the protocol is simply:

        SIZE    = [0-9]{1,9}
        COLON   = ':'
        DATA    = (.*)
        TYPE    = ('#' | '}' | ']' | ',' | '!' | '~' | '^')
        payload = (SIZE COLON DATA TYPE)+

    Each of these elements is defined as:

SIZE    A ascii encoded integer that is no longer than 9 digits long, and anyone
        receiving a message can abort at any length lower than that limit.

COLON   A colon character.

DATA    A sequence of bytes that is SIZE in length and can include all of the TYPE
        chars since the SIZE is used, not the terminal TYPE char.

TYPE     A character indicating what type the DATA is.  Each TYPE is used to
        determine the contents and maps to:

   ,    string (byte array)
   #    integer
   ^    float
   !    boolean of 'true' or 'false'
   ~    null always encoded as 0:~
   }    Dictionary which you recurse into to fill with key=value pairs inside the payload contents.
   ]    List which you recurse into to fill with values of any type.

"""

import json
import logging
import sys

import cpppo
from   cpppo.server import network

address				= ('', 8008)

log				= logging.getLogger( "tnet.srv" )

bytes_conf 			= {
    "alphabet":	cpppo.type_bytes_iter,
    "typecode":	cpppo.type_bytes_array_symbol,
}

def data_parser( **kwds ):
    """Parses raw bytes into .data, by default using ..size to denote the amount.  """
    kwds.setdefault( "name", "DATA" )
    kwds.setdefault( "context", "data" )
    kwds.setdefault( "repeat", "..size" )
    return cpppo.dfa(
        initial=cpppo.state_input( name="BYTE", terminal=True, **bytes_conf ), **kwds )

def tnet_machine( name="TNET", context="tnet" ):
    """Accept a sentence of input bytes matching a tnetstring, and then
    loop.  Sub-machine terminates at earliest match (non-greedy), causing
    echo.transition to trigger .process (which resets our sub-machine to initial
    state), and then we move to the next state (loops), allowing us to
    immediately run."""

    class tnet_parser( cpppo.state_input ):
        TYPES			= (b'#'[0], b'}'[0], b']'[0], b','[0],
                                   b'$'[0], b'!'[0], b'~'[0], b'^'[0])

        def process( self, source, machine=None, path=None, data=None ):
            """Convert the collected data according to the type"""
            tntype		= next( source )
            ours		= self.context( path )
            raw			= ours + '...data.input'
            src			= ( data[raw].tostring() if sys.version_info[0] < 3
                                    else data[raw].tobytes() )

            if tntype == b','[0]:
                log.info("%5d bytes  data: %s", len( src ), cpppo.reprlib.repr( src ))
                data[ours]	= src
            elif tntype == b'$'[0]:
                log.info("%5d string data: %s", len( src ), cpppo.reprlib.repr( src ))
                data[ours]	= src.decode( 'utf-8' )
            elif tntype == b'#'[0]:
                data[ours]	= int( src )
                log.info("%5d int    data: %s == %s", len( src ), cpppo.reprlib.repr( src ),
                         cpppo.reprlib.repr( data[ours] ))
            elif tntype == b'~'[0]:
                assert 0 == len( src )
                data[ours]	= None
            else:
                assert False, "Invalid tnetstring type: %s" % tntype
                
    bytes_conf 			= {
        "alphabet":	cpppo.type_bytes_iter,
        "typecode":	cpppo.type_bytes_array_symbol,
    }

    SIZE			= cpppo.dfa( name="SIZE", 
                                             initial=cpppo.integer_bytes(
                                                 name="INT", context="size", decode='ascii', terminal=True ))
    COLON			= cpppo.state_drop( name="COLON", **bytes_conf )
    DATA			= data_parser( name="DATA", context="data", repeat="..size" )
    TYPE			= tnet_parser( name="TYPE", context="type", terminal=True,
                                                     **bytes_conf )

    SIZE[b':'[0]]		= COLON
    COLON[None]			= DATA
    for t in tnet_parser.TYPES:
        DATA[t]			= TYPE

    # Recognize a TNET string and then terminate, resetting to automatically
    # recognize another
    return cpppo.dfa( name=name, context=context, initial=SIZE, terminal=True )


def tnet_server( conn, addr ):
    """Serve one tnet client 'til EOF; then close the socket"""
    source			= cpppo.chainable()
    with tnet_machine( "tnet_%s" % addr[1] ) as tnet_mesg:
        eof			= False
        while not eof:
            data		= cpppo.dotdict()
            # Loop blocking for input, while we've consumed input from source since the last time.
            # If we hit this again without having used any input, we know we've hit a symbol
            # unacceptable to the state machine; stop
            for mch, sta in tnet_mesg.run( source=source, data=data ):
                if sta is not None:
                    continue
                # Non-transition; check for input, blocking if non-terminal and none left.  On
                # EOF, terminate early; this will raise a GeneratorExit.
                timeout		= 0 if tnet_mesg.terminal or source.peek() is not None else None
                msg		= network.recv( conn, timeout=timeout ) # blocking
                if msg is not None:
                    eof		= not len( msg )
                    log.info( "%s: recv: %5d: %s", tnet_mesg.name_centered(), len( msg ),
                              "EOF" if eof else cpppo.reprlib.repr( msg )) 
                    source.chain( msg )
                    if eof:
                        break

            # Terminal state (or EOF).
            log.detail( "%s: byte %5d: data: %r", tnet_mesg.name_centered(), source.sent, data )
            if tnet_mesg.terminal:
                res			= json.dumps( data.tnet.type.input, indent=4, sort_keys=True )
                conn.send(( res + "\n\n" ).encode( "utf-8" ))
    
        log.info( "%s done", tnet_mesg.name_centered() )


def main():
    logging.basicConfig( **cpppo.log_cfg )
    return network.server_main( address=address, target=tnet_server )


if __name__ == "__main__":
    sys.exit( main() )
