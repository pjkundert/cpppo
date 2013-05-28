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

import array
import codecs
import errno
import json
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

address				= ('0.0.0.0', 8008)

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "tnet.srv" )

class integer_parser( cpppo.regex_bytes ):
    """Collects a string of digits, and converts them to an integer in the data
    artifact at path.context 'value' by default."""
    def __init__( self, initial="\d+", context="value", **kwds ):
        super( integer_parser, self ).__init__( initial=initial, context=context, **kwds )
        
    def terminate( self, exception, machine=None, path=None, data=None ):
        """Once our machine has accepted a sequence of digits (into data context 'value.input'), convert to
        an integer and store in 'value'"""
        if exception is not None:
            log.warning( "%s: Not parsing integer due to: %r", self.name_centered(), exception )
            return

        ours			= self.context( path )
        subs			= self.initial.context( ours )
        log.info( "%s: recv: data[%s] = int( data[%s]: %r)", self.name_centered(),
                  ours, subs, data[subs] if subs in data else data)
        data[ours]		= int( data[subs].tostring() )

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
        codes			= (b'#'[0], b'}'[0], b']'[0], b','[0],
                                   b'$'[0], b'!'[0], b'~'[0], b'^'[0])

        def process( self, source, machine=None, path=None, data=None ):
            """Convert the collected data according to the type"""
            tntype		= next( source )
            ours		= self.context( path )
            raw			= ours + '...data.input'
            src			= ( data[raw].tostring() if sys.version_info.major < 3
                                    else data[raw].tobytes() )

            if tntype == b','[0]:
                log.info("%5d bytes  data: %s", len( src ), reprlib.repr( src ))
                data[ours]	= src
            elif tntype == b'$'[0]:
                log.info("%5d string data: %s", len( src ), reprlib.repr( src ))
                data[ours]	= src.decode( 'utf-8' )
            elif tntype == b'#'[0]:
                data[ours]	= int( src )
                log.info("%5d int    data: %s == %s", len( src ), reprlib.repr( src ),
                         reprlib.repr( data[ours] ))
            elif tntype == b'~'[0]:
                assert 0 == len( src )
                data[ours]	= None
            else:
                assert False, "Invalid tnetstring type: %s" % tntype
                
    bytes_conf 			= {
        "alphabet":	cpppo.type_bytes_iter,
        "typecode":	cpppo.type_bytes_array_symbol,
    }

    SIZE			= integer_parser( name="SIZE", context="size" )
    COLON			= cpppo.state_discard( name="COLON", **bytes_conf )
    DATA			= data_parser( name="DATA", context="data", repeat="..size" )
    TYPE			= tnet_parser( name="TYPE", context="type", terminal=True,
                                                     **bytes_conf )
    SIZE[b':'[0]]		= COLON
    SIZE[True]			= None  # SIZE terminal, but only : acceptable

    COLON[None]			= DATA
    for t in tnet_parser.codes:
        DATA[t]			= TYPE
    DATA[True]			= None # DATA terminal, but only TNET codes acceptable

    # Recognize a TNET string and then terminate, resetting automatically
    # recognize another
    return cpppo.dfa( name=name, context=context, initial=SIZE )


def tnet_server( conn, addr ):
  """Serve one tnet client 'til EOF; then close the socket"""
  with tnet_machine( "tnet_%s" % addr[1] ) as tnet_mesg:
    source			= cpppo.chainable()
    # Loop blocking for input, while we've consumed input from source since the last time.  If we
    # hit this again without having used any input, we know we've hit a symbol unacceptable to the
    # state machine; stop
    done			= False
    while not done:
        data			= cpppo.dotdict()
        for mch, sta in tnet_mesg.run( source=source, data=data ):
            if sta is None:
                # Our machine (or a sub-machine) has not be
                if source.peek() is None:
                    # Out of input, no complete line of echo input acquired.  Wait for more.
                    log.debug( "%s: end of input", mch.name_centered() )
                    msg		= network.recv( conn, timeout=None ) # blocking
                    log.info( "%s: recv: %5d: %s", mch.name_centered(), 
                              len( msg ), reprlib.repr( msg ) if msg else "EOF" ) 
                    done 	= not msg   	# None or empty; EOF
                    if done:
                        break
                    source.chain( msg )
                elif mch is tnet_machine:
                    #  Unrecognized input by TNET machine (not some sub-machine).  Drop some, if we
                    # are currently in-between TNET strings (a new one hasn't yet been started)
                    assert tnet_mesg.current in (None, tnet_mesg.initial), \
                        "Unrecognized symbol while parsing TNET string: %r" % source.peek()
                    log.warning( "%s: dropping: %r", mch.name_centered(),
                                 next( source ))
            else:
                log.info( "%s: byte %5d: data: %r", mch.name_centered(), source.sent, data )

        if sta is not None:
            # Reached a terminal state.  Return TNET data payload as JSON, and
            # carry on (tnet_mesg will have been reset)
            log.info( "%s: byte %5d: data: %r", tnet_mesg.name_centered(), source.sent, data )
            res			= json.dumps( data.tnet.type.input, indent=4, sort_keys=True )
            log.info( "%s: byte %5d: result: %r", tnet_mesg.name_centered(), source.sent, res )
            conn.send(( res + "\n\n" ).encode( "utf-8" ))

    log.info( "%s done: %r", tnet_mesg.name_centered(), data )
    if source.peek() is not None:
        log.warning( "parsing failed at input symbol %d", source.sent )


def main():
    return network.server_main( address=address, target=tnet_server )


if __name__ == "__main__":
    sys.exit( main() )
