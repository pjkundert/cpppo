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

from .parser import *

address				= ('0.0.0.0', 44818)

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "enip.srv" )

def enip_srv( conn, addr, enip_process=None ):
    """Serve one Ethernet/IP client 'til EOF; then close the socket.  Parses headers 'til either the
    parser fails (the Client has submitted an un-parsable request), or the request handler fails.
    Use the supplied enip_process function to process each parsed EtherNet/IP CIP frame.

    If a partial EtherNet/IP header is parsed and an EOF is received, the enip_header parser will
    raise an AssertionError, and we'll simply drop the connection.  If we receive a valid header and
    request, the supplied enip_process function is expected to formulate an appropriate error
    response, and we'll continue processing requests."""
    name			= "enip_%s" % addr[1]
    log.normal( "EtherNet/IP Server %s begins serving peer %s", name, addr )

    source			= cpppo.rememberable()
    with enip_machine( name=name ) as enip_mesg:
        try:
            assert enip_process is not None, \
                "Must specify an EtherNet/IP processing function via 'enip_process'"
            requests		= 0
            received		= 0
            eof			= False
            while not eof:
                data		= cpppo.dotdict()
                source.forget()
                # If no/partial EtherNet/IP header received, parsing will fail with a NonTerminal
                # Exception (dfa exits in non-terminal state).
                for mch,sta in enip_mesg.run( path='request', source=source, data=data ):
                    if sta is None:
                        # No more transitions available.  Wait for input.  Either None (should never
                        # be seen due to non-blocking recv) or b'' will lead to termination.
                        # Non-blocking, if we still have input available to process right now.
                        msg	= network.recv( conn, timeout=None if source.peek() is None else 0 )
                        if msg is not None:
                            received += len( msg )
                            eof	= not len( msg )
                            log.detail( "%s recv: %5d: %s", enip_mesg.name_centered(),
                                        len( msg ) if msg is not None else 0, reprlib.repr( msg ))
                            if not eof:
                                source.chain( msg )
                        else:
                            log.detail( "%s recv:   N/A", enip_mesg.name_centered() )

                # Terminal state and EtherNet/IP header recognized, or clean EOF (no partial
                # message); process and return response
                log.info( "%s req. data: %s", enip_mesg.name_centered(), enip_format( data ))
                if data:
                    requests   += 1
                try:
                    # TODO: indicate successful composition of response?  enip_process must be able
                    # to handle no request, indicating the clean termination of the session.
                    enip_process( addr, source=source, data=data )
                    if 'response' in data:
                        rpy	= enip_encode( data.response )
                        log.detail( "%s send: %5d: %s", enip_mesg.name_centered(),
                                    len( rpy ), reprlib.repr( rpy ))
                        conn.send( rpy )
                except:
                    log.error( "Failed request: %s", enip_format( data ))
                    raise

            processed			= source.sent
        except:
            # Parsing failure.  We're done.  Suck out some remaining input to give us some context.
            processed			= source.sent
            memory			= bytes(bytearray(source.memory))
            pos				= len( source.memory )
            future			= bytes(bytearray( b for b in source ))
            where			= "at %d total bytes:\n%s\n%s (byte %d)" % (
                processed, repr(memory+future), '-' * (len(repr(memory))-1) + '^', pos )
            log.warning( "%s failed with exception:\n%s\nEnterNet/IP parsing error %s", enip_mesg.name,
                         ''.join( traceback.format_exception( *sys.exc_info() )), where )
            raise
        finally:
            # Not strictly necessary to close (network.server_main will discard the socket, implicitly
            # closing it), but we'll do it explicitly here in case the thread doesn't die for some
            # other reason.
            log.normal( "%s done; processed %3d request%s over %5d byte%s/%5d received", name,
                        requests,  " " if requests == 1  else "s",
                        processed, " " if processed == 1 else "s", received )
            sys.stdout.flush()
            conn.close()


def main( **kwds ):
    # TODO: parse arguments to select the appropriate EtherNet/IP CIP processor, if one isn't
    # specified
    return network.server_main( address=address, target=enip_srv, **kwds )

if __name__ == "__main__":
    sys.exit( main() )
