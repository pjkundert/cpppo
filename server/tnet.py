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

import argparse
import json
import logging
import sys

import cpppo
from   cpppo.server import network

address				= ('', 8008)

log				= logging.getLogger( "tnet" )

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
            src			= b'' if raw not in data else (
                data[raw].tostring() if sys.version_info[0] < 3
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


def tnet_from( conn, addr,
               server	= cpppo.dotdict({'done': False}),
               timeout	= None,
               latency	= None,
               ignore	= None,
               source	= None ):	# Provide a cpppo.chainable, if desire, to receive into and parse from
    """Parse and yield TNET messages from a socket w/in timeout, blocking 'til server.done or EOF
    between messages.  If ignore contains symbols, they are ignored between TNET messages (eg. b'\n').

    An absense of a TNET string within 'timeout' will yield None, allowing the user to decide to
    fail or continue trying for another 'timeout' period.  A 0 timeout will "poll", and a None
    timeout will simply wait forever (the default).  If desired, a separate 'latency' can be
    supplied, in order to pop out regularly and check server.done (eg. to allow a server Thread to
    exit cleanly).

    """
    if source is None:
        source			= cpppo.chainable()
    with tnet_machine( "tnet_%s" % addr[1] ) as engine:
        eof			= False
        while not ( eof or server.done ):
            while ignore and source.peek() and source.peek() in ignore:
                next( source )
            data		= cpppo.dotdict()
            started		= cpppo.timer()		# When did we start the current attempt at a TNET string?
            for mch,sta in engine.run( source=source, data=data ):
                if sta is not None or source.peek() is not None:
                    continue
                # Non-transition state, and we need more data: check for more data, enforce timeout.
                # Waits up to latency, or remainder of timeout -- or forever, if both are None.
                duration	= cpppo.timer() - started
                msg		= None
                while msg is None and not server.done: # Get input, forever or 'til server.done
                    remains	= latency if timeout is None else min(	# If no timeout, wait for latency (or forever, if None)
                        timeout if latency is None else latency,	# Or, we know timeout is numeric; get min of any latency
                        max( timeout - duration, 0 ))			#  ... and remaining unused timeout
                    log.info( "%s: After %7.3fs, awaiting symbols (after %d processed) w/ %s recv timeout",
                              engine.name_centered(), duration, source.sent,
                              remains if remains is None else ( "%7.3fs" % remains ))
                    msg		= network.recv( conn, timeout=remains )
                    duration	= cpppo.timer() - started
                    if msg is None and timeout is not None and duration >= timeout:
                        # No data w/in given timeout expiry!  Inform the consumer, and then try again w/ fresh timeout.
                        log.info( "%s: After %7.3fs, no TNET message after %7.3fs recv timeout",
                              engine.name_centered(), duration, remains )
                        yield None
                        started	= cpppo.timer()
                # Only way to get here without EOF/data, is w/ server.done
                if server.done:
                    break
                assert msg is not None
                # Got EOF or data
                eof		= len( msg ) == 0
                log.info( "%s: After %7.3fs, recv: %5d: %s",
                          engine.name_centered(), duration, len( msg ),
                          'EOF' if eof else cpppo.reprlib.repr( msg ))
                if eof:
                    break
                source.chain( msg )

            # Terminal state, or EOF, or server.done.  Only yield another TNET message if terminal. 
            duration		= cpppo.timer() - started
            if engine.terminal:
                log.debug( "%s: After %7.3fs, found a TNET: %r", engine.name_centered(), duration, data.tnet.type.input )
                yield data.tnet.type.input # Could be a 0:~ / null ==> None

        log.detail( "%s: done w/ %s", engine.name_centered(),
                    ', '.join( ['EOF'] if eof else [] + ['done'] if server.done else [] ))


def tnet_server_json( conn, addr, timeout=None, latency=None, ignore=None ):
    """Wait forever for TNET messages, and echo the JSON-encoded payload back to the client."""
    for msg in tnet_from( conn, addr, timeout=timeout, latency=latency, ignore=ignore ):
        try:
            res			= json.dumps( msg, indent=4, sort_keys=True )
            rpy			= ( res + "\n\n" ).encode( "utf-8" )
        except TypeError: # eg. raw bytes
            rpy			= msg
        conn.sendall( rpy )


def main( argv=None ):
    ap				= argparse.ArgumentParser(
        description = "TNET Network Client",
        epilog = "" )

    ap.add_argument( '-v', '--verbose', action="count",
                     default=0, 
                     help="Display logging information." )
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( '-T', '--timeout', default=None,
                     help="Optional timeout on receiving TNET string; responds w/ None upon timeout" )
    ap.add_argument( '-L', '--latency', default=None,
                     help="Optional latency on checking server.done" )
    ap.add_argument( '-a', '--address', default=None,
                     help="The local interface[:port] to bind to (default: {iface}:{port})".format(
                         iface=address[0], port=address[1] ))
    args			= ap.parse_args( argv )
    
    idle_service		= []

    # Set up logging level (-v...) and --log <file>, handling log-file rotation
    levelmap 			= {
        0: logging.WARNING,
        1: logging.NORMAL,
        2: logging.DETAIL,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    cpppo.log_cfg['level']	= ( levelmap[args.verbose] 
                                    if args.verbose in levelmap
                                    else logging.DEBUG )
    if args.log:
        cpppo.log_cfg['filename']= args.log
 
    logging.basicConfig( **cpppo.log_cfg )

    timeout			= None if args.timeout is None else float( args.timeout )
    latency			= None if args.latency is None else float( args.latency )

    bind			= address
    if args.address:
        host,port		= cpppo.parse_ip_port( args.address, default=address )
        bind			= str(host),int(port)

    return network.server_main(
        address	= bind,
        target	= tnet_server_json,
        kwargs	= dict(
            timeout	= timeout,
            latency	= latency,
            ignore	= b'\n'
        )
    )


if __name__ == "__main__":
    sys.exit( main() )
