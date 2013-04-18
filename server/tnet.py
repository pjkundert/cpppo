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

import errno
import logging
import os
import sys
import threading
import time
import traceback
try:
    from reprlib import repr as repr
except ImportError:
    from repr import repr as repr

import cpppo
from   cpppo    import misc
import cpppo.server
from   .network import *

address				= ('0.0.0.0', 8008)

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "tnet.srv" )

class integer_parser( cpppo.fsm_bytes ):
    """Collects a string of digits, and converts them to an integer in the data
    artifact at path.context 'value' by default."""
    def __init__( self, initial="\d+", context="value", **kwds ):
        super( integer_parser, self ).__init__( initial=initial, context=context, **kwds )
        
    def process( self, source, machine=None, path=None, data=None ):
        """Once our machine has accepted a sequence of digits (into data context
        'value_'), convert to an integer and store in 'value'"""
        ours			= self.context( path )
        subs			= self.initial.context( ours )
        log.info("recv: data[%s] = data[%s]: %r", ours, subs, data[subs] if subs in data else data)
        data[ours]		= int( data[subs].tostring() )
        del data[subs]

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

    class tnet_type( cpppo.state_input ):

        codes			= ('#', '}', ']', ',', '!', '~', '^')

        def process( self, source, machine=None, path=None, data=None ):
            """Convert the collected data according to the type"""
            tntype		= next( source )
            ours		= self.context( path )
            subs		= self.initial.context( ours, '_' )
            src			= data[subs]

            if tntype == ',':
                log.info("%5d bytes raw data: %s", len( src ), repr( src ) )
                data[ours]	= src.tobytes()
            elif tntype == '#':
                data[ours]	= int( src.tostring() )
                log.info("%5d bytes int data: %s == ", len( src ), repr( src ), repr( data[ours] ))
            elif tntype == '~':
                assert 0 == len( data[src] )
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
    DATA			= data_parser( name="DATA", context="data", repeat="..size" )

    TYPE			= tnet_type( name="TYPE", context="type", terminal=True, **bytes_conf )

    SIZE[':']			= DATA
    for t in tnet_type.codes:
        DATA[t]			= TYPE

    machine			= tnet_main( name="TNET", context="tnet", initial=SIZE )
    machine[None]		= machine

    return machine


def echo_server( conn, addr ):
    """Serve one tnet client 'til EOF; then close the socket"""
    source			= cpppo.chainable()
    data			= cpppo.dotdict()
    tnet_line			= tnet_machine( "tnet_%s" % addr[1] )
    sequence			= tnet_line.run( source=source, data=data, greedy=False )
    while True:
        msg			= recv( conn, timeout=None ) # blocking
        if not msg: # None or empty
            log.info( "%s recv: %s", misc.centeraxis( echo_line, 25, clip=True ),
                      repr( msg ) if msg else "EOF" )
            break
        source.chain( msg )
        log.info( "%s recv: %5d: %s", misc.centeraxis( echo_line, 25, clip=True ), 
                  len( msg ), repr( msg ))

        # See if a line has been recognized, stopping at terminal state
        for mch, sta in sequence:
            if sta is None:
                break # No more transitions available on source input, but not terminal
        if sta:
            # Terminal state.  Echo, and carry on
            log.info( "%s: data: %r", misc.centeraxis( echo_line, 25, clip=True ), data )
            conn.send( data.echo )
            echo_line.reset()
            sequence		= echo_line.run( source=source, data=data, greedy=False )
        else:
            # Out of input, no complete line of echo input acquired.  Wait for more.
            log.debug( "%s: end of input", misc.centeraxis( echo_line, 25, clip=True ))
 
    log.info( "%s done: %s" % ( misc.centeraxis( echo_line, 25, clip=True ), repr( data )))

class server_thread( threading.Thread ):
    """A generic server handler.  Supply a handler taking an open socket
    connection to target=... Assumes at least one or two arg=(conn,[addr,[...]])"""
    def __init__( self, **kwds ):
        super( server_thread, self ).__init__( **kwds )
        self.conn		= kwds['args'][0]
        self.addr	        = kwds['args'][1] if len( kwds['args'] ) > 1 else None

    def run( self ):
        log.info("%s.echo service PID [%5d/%5d] starting on %r",
                 __package__, os.getpid(), self.ident, self.addr )
        try:
            super( server_thread, self ).run()
        except Exception as exc:
            log.warning( "%s.echo service failure: %r\n%s", __package__,
                         exc, traceback.format_exc() )
        log.info("%s.echo service PID [%5d/%5d] stopping on %r",
                 __package__, os.getpid(), self.ident, self.addr )

    def join( self ):
        try:
            self.conn.shutdown( socket.SHUT_WR )
        except:
            pass
        result			= super( server_thread, self ).join()
        if not self.is_alive():
            log.info("%s.echo service PID [%5d/%5d] complete on %r", 
                     __package__, os.getpid(), self.ident, self.addr )


def main():
    sock			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 ) # Avoid delay on next bind due to TIME_WAIT
    sock.bind( address )
    sock.listen( 100 ) # How may simultaneous unaccepted connection requests

    threads			= {}
    log.info("%s.echo service PID [%5d] running on %r", __package__, os.getpid(), address )
    done			= False
    while not done:
        try:
            acceptable		= accept( sock, timeout=.1 )
            if acceptable:
                conn, addr	= acceptable
                threads[addr]	= server_thread( target=echo_server, args=(conn, addr) )
                threads[addr].start()
        except KeyboardInterrupt as exc:
            log.warning("%s.echo service termination: %r", __package__, exc )
            done		= True
        except Exception as exc:
            log.warning("%s.echo service failure: %r\n%s", __package__,
                        exc, traceback.format_exc() )
            done		= True
        finally:
            for addr in list( threads ):
                if done or not threads[addr].is_alive():
                    threads[addr].join()
                    del threads[addr]

    sock.close()
    log.info("%s.echo service PID [%5d] shutting down", __package__, os.getpid() )
    return 0

if __name__ == "__main__":
    sys.exit(main())
