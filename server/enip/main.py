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
#log.setLevel( logging.DEBUG )

def enip_server( conn, addr, enip_process=None ):
    """Serve one Ethernet/IP client 'til EOF; then close the socket.  Parses headers 'til either the
    parser fails (the Client has submitted an un-parsable request), or the request handler fails.
    Use the supplied enip_process function to process each parsed EtherNet/IP CIP frame."""
    try:
        source			= cpppo.chainable()
        with enip_machine( "enip_%s" % addr[1] ) as enip_mesg:
            done		= False
            while not done:
                data		= cpppo.dotdict()
                beg		= source.sent
                req		= b''
                for mch,sta in enip_mesg.run( source=source, data=data ):
                    if sta is None:
                        # No more transitions available.  Wait for input.
                        # Either None or b'' will lead to termination
                        msg	= network.recv( conn, timeout=None ) # blocking
                        done	= not msg # None or empty; EOF
                        log.debug( "%s recv: %5d: %s", enip_mesg.name_centered(),
                                  len( msg ) if msg else 0, reprlib.repr( msg ))
                        source.chain( msg )
                        req    += msg or b''
                # State machine ended, either by reaching a terminal state or failing to advance.
                # Stop if we reached EOF (done) cleanly without starting a new request (not req).
                off		= source.sent - beg
                where		= "at %d total bytes:\n%s\n%s (byte %d)" % (
                    source.sent, repr(bytes(req)), '-' * (len(repr(bytes(req[:off])))-1) + '^', off )
                if req:
                    assert sta is not None, "Unrecognized request " + where 
                elif done:
                    continue

                # Terminal state; EtherNet/IP request recognized; return response 
                log.info( "%s EtherNet/IP request %s", enip_mesg.name_centered(), where )
                try:
                    conn.send( enip_encode( enip_process( addr, data )))
                except:
                    log.error( "Failed request %s\swith data: %s", where, enip_format( data ))
                    raise
                
            log.info( "%s done: %s" % ( enip_mesg.name_centered(), reprlib.repr( data )))
    except Exception as exc:
        log.warning( "%s failed with exception %s", enip_mesg.name_centered(), exc )
        raise
    except:
        # Unknown exception type; probably bad news
        typ, exc, tbk	= sys.exc_info()
        exception		= exc
        log.warning( "%s failed with unknown exception %s\n%s", self.name_centered(),
                     exc, ''.join( traceback.format_exception( typ, val, tbk )))
        raise
    finally:
        # Not strictly necessary to close, but we'll 
        log.info( "%s close", enip_mesg.name_centered() )
        conn.close()

def enip_process( addr, data ):
    """Default EtherNet/IP CIP processing function."""
    raise Exception("Unimplemented")

def main( **kwds ):
    # TODO: parse arguments to select the appropriate EtherNet/IP CIP processor, if one isn't
    # specified
    return network.server_main( address=address, target=enip_server, **kwds )

if __name__ == "__main__":
    sys.exit( main() )
