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
enip		-- An server recognizing an Ethernet/IP protocol subset

USAGE
    python -m cpppo.server.enip

BACKGROUND


"""

import array
import codecs
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

address				= ('0.0.0.0', 44818)

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "enip.srv" )

bytes_conf 			= {
    "alphabet":	cpppo.type_bytes_iter,
    "typecode":	cpppo.type_bytes_array_symbol,
}

def data_parser( **kwds ):
    """Parses raw data """
    kwds.setdefault( "name", "DATA" )
    kwds.setdefault( "context", "data" )
    kwds.setdefault( "repeat", "..size" )
    return cpppo.dfa(
        initial=cpppo.state_input( name="BYTE", terminal=True, **bytes_conf ), **kwds )

# Our FSM is described in str symbols; synonymous for bytes on Python2, but
# utf-8 on Python3 so encode them

def tnet_machine( name=None ):
    """Accept a sentence of input bytes matching a tnetstring, and then
    loop.  Sub-machine terminates at earliest match (non-greedy), causing
    echo.transition to trigger .process (which resets our sub-machine to initial
    state), and then we move to the next state (loops), allowing us to
    immediately run."""

    class tnet_parser( cpppo.state_input ):
        codes			= ('#', '}', ']', ',', '$', '!', '~', '^')

        def process( self, source, machine=None, path=None, data=None ):
            """Convert the collected data according to the type"""
            tntype		= next( source )
            ours		= self.context( path )
            raw			= self.context( ours, '...data_input' )
            src			= data[raw].tostring() if sys.version_info.major < 3 else data[raw].tobytes()

            if tntype == ',':
                log.info("%5d bytes  data: %s", len( src ), reprlib.repr( src ))
                data[ours]	= src
            elif tntype == '$':
                log.info("%5d string data: %s", len( src ), reprlib.repr( src ))
                data[ours]	= src.decode( 'utf-8' )
            elif tntype == '#':
                data[ours]	= int( src )
                log.info("%5d int    data: %s == %d", len( src ), reprlib.repr( src ),
                         reprlib.repr( data[ours] ))
            elif tntype == '~':
                assert 0 == len( src )
                data[ours]	= None
            else:
                assert False, "Invalid tnetstring type: %s" % tntype
                

    class tnet_main( cpppo.dfa ):
        def process( self, source, machine=None, path=None, data=None ):
            self.reset()

    bytes_conf 			= {
        "alphabet":	cpppo.type_bytes_iter,
        "typecode":	cpppo.type_bytes_array_symbol,
    }

    SIZE			= integer_parser( name="SIZE", context="size" )
    COLON			= cpppo.state_discard( name="COLON", **bytes_conf )
    DATA			= data_parser( name="DATA", context="data", repeat="..size" )
    TYPE			= tnet_parser( name="TYPE", context="type", terminal=True,
                                                     **bytes_conf )

    SIZE[':']			= COLON
    COLON[None]			= DATA
    for t in tnet_parser.codes:
        DATA[t]			= TYPE

    machine			= tnet_main( name="TNET", context="tnet", initial=SIZE )
    machine[None]		= machine

    return machine


def enip_server( conn, addr ):
    """Serve one Ethernet/IP client 'til EOF; then close the socket"""
    source			= cpppo.chainable()
    data			= cpppo.dotdict()
    enip_mesg			= enip_machine( "enip_%s" % addr[1] )
    sequence			= enip_mesg.run( source=source, data=data, greedy=False )
    while True:
        msg			= recv( conn, timeout=None ) # blocking
        if not msg: # None or empty
            log.info( "%s recv: %s", misc.centeraxis( enip_mesg, 25, clip=True ),
                      reprlib.repr( msg ) if msg else "EOF" )
            break
        source.chain( msg )
        log.info( "%s recv: %5d: %s", misc.centeraxis( enip_mesg, 25, clip=True ), 
                  len( msg ), reprlib.repr( msg ))

        # See if a line has been recognized, stopping at terminal state
        for mch, sta in sequence:
            if sta is None:
                break # No more transitions available on source input, but not terminal
        if sta:
            # Terminal state.  Echo, and carry on
            log.info( "%s: data: %r", misc.centeraxis( enip_mesg, 25, clip=True ), data )
            conn.send( data.echo )
            enip_mesg.reset()
            sequence		= enip_mesg.run( source=source, data=data, greedy=False )
        else:
            # Out of input, no complete line of echo input acquired.  Wait for more.
            log.debug( "%s: end of input", misc.centeraxis( enip_mesg, 25, clip=True ))
 
    log.info( "%s done: %s" % ( misc.centeraxis( enip_mesg, 25, clip=True ), reprlib.repr( data )))



def main():
    server_main( address=address, target=enip_server )

if __name__ == "__main__":
    sys.exit(main())
