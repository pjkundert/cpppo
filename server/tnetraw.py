#! /usr/bin/env python3

# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2020, Dominion R&D Corp.
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
__email__                       = "perry@dominionrnd.com"
__copyright__                   = "Copyright (c) 2020 Dominion R&D Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import argparse
import json
import logging
import sys

import cpppo
from   cpppo.server import network

address			= ('', 8008)

log			= logging.getLogger( 'tnetraw' )

def tnet_from( conn, addr,
               server	= cpppo.dotdict({'done': False}),
               timeout	= None,
               latency	= None,		# Optionally check server.done regularly
               ignore	= None,		# Optional symbols (bytes) to ignore
               source	= None ):	# Provide a cpppo.chainable, if desire, to receive into and parse from
    """Simplest possible TNET string parser generator, from a recv-able socket connection.  Currently
    only receives TNET strings of the form <int>: ... UTF-8 encoded str ...$

    Does not support a symbol source other than conn.

    Yields a None if complete TNET not found before timeout.  If desired, a separate 'latency' can
    be supplied, in order to pop out regularly and check server.done (eg. to allow a server Thread
    to exit cleanly).

    """
    assert source is None, \
        "Unsupported source: {source!r}".format( source=source )
    while not server.done:
        started		= cpppo.timer()

        def recv( maxlen ):
            duration	= cpppo.timer() - started
            remains	= None if timeout is None else max( 0, timeout - duration )
            remains	= latency if timeout is None else min(	# If no timeout, wait for latency (or forever, if None)
                timeout if latency is None else latency,	# Or, we know timeout is numeric; get min of any latency
                max( timeout - duration, 0 ))			#  ... and remaining unused timeout
            return network.recv( conn, maxlen=maxlen, timeout=remains )

        length,c	= b'',b'0'
        while not server.done and c in b'01234567889' or ( ignore and c in ignore ):
            if not ignore or c not in ignore:
                assert c in b'0123456789', "Expected TNET size symbol, not {c!r}".format( c=c ) # EOF/timeout
                length += c
            c		= None
            while not server.done and c is None:
                c	= recv( 1 )
                if c is None and timeout is not None and cpppo.timer() - started > timeout:
                    # No data w/in given timeout expiry!  Inform the consumer, and then try again w/ fresh timeout.
                    yield None
                    started = cpppo.timer()
        if server.done or c == b'': return # done/EOF
        assert c == b':', "Expected TNET <size> separator ':', not {c!r}".format( c=c )
        length		= int( length )

        # Harvest the desired payload length.
        payload,c	= b'',None
        while not server.done and c is None and len( payload ) < length:
            c		= recv( length - len( payload ))
            if c is None and timeout is not None and cpppo.timer() - started > timeout:
                yield None
                started	= cpppo.timer()
                continue
            payload    += c
        if server.done or c == b'': return # done/EOF
        assert len( payload ) == length, \
            "Expected TNET {length}-byte payload; got {actual_length}-byte {actual}".format(
                length=length, actual_length=len( payload ), actual=cpppo.reprlib.repr( payload ))

        c		= None
        while not server.done and c is None:
            c		= recv( 1 )
            if c is None and timeout is not None and cpppo.timer() - started > timeout:
                yield None
                started	= cpppo.timer()
        if server.done or c == b'': return # done/EOF
        if c == b'$':
            yield payload.decode( 'utf-8' )
            continue
        elif c == b',':
            yield payload
            continue
        elif c == b'#':
            yield int( payload )
            continue
        elif c == b'~':
            assert 0 == len( payload )
            yield None # TODO: Indistinguishable from timeout?
            continue

        raise "Expected TNET payload type, not {c}".format( c=c )


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
        description = "TNET Network Client using raw parser",
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
