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
enip.logix	-- Implements a Logix-like PLC subset

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

from . import (parser, device)

log				= logging.getLogger( "enip.lgx" )

initialized			= False

def setup():
    """Create the required CIP device Objects"""
    Id				= device.Identity()		# Class 0x01, Instance 1
    Mr				= device.Message_Router()	# Class 0x02, Instance 1
    Cm				= device.Connection_Manager()	# Class 0x06, Instance 1

def process( addr, source, data ):
    """Processes an incoming EtherNet/IP encapsulated request, and produces a response with a prepared
    encapsulated reply.  Returns True while session lives, False when the session is cleanly
    terminated.  Raises an exception when a fatal protocol processing error occurs, and the session
    should be terminated forcefully.

    """
    if not initialized:
        setup()

    if not data:
        return False # Incoming EOF.

    source			= cpppo.rememberable( data.request.enip.input )
    try:
        # Parse the encapsulated EtherNet/IP request.
        log.detail( "EtherNet/IP CIP Request  (Client %16s): %r", addr, data.request.enip.input )
        Mr			= device.lookup( class_id=0x02, instance_id=1 )
        with Mr.parser as machine:
            for i,(m,s) in enumerate( machine.run( path='request.enip', source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                            machine.name_centered(), i, s, source.sent, source.peek(), data )

        log.normal( "EtherNet/IP CIP Request  (Client %16s): %s", addr,
                    parser.enip_format( data.request ))
        proceed			= Mr.process( data )
        log.normal( "EtherNet/IP CIP Response (Client %16s): %s", addr,
                    parser.enip_format( data.response ))

        rpy			= Mr.parser.produce( data.response.enip.CIP )
        data.response.enip.input= array.array( cpppo.type_bytes_array_symbol, rpy )
        log.detail( "EtherNet/IP CIP Response (Client %16s):  %r", addr, data.response.enip.input )
        return proceed
    except:
        # Parsing failure.  We're done.  Suck out some remaining input to give us some context.
        processed		= source.sent
        memory			= bytes(bytearray(source.memory))
        pos			= len( source.memory )
        future			= bytes(bytearray( b for b in source ))
        where			= "at %d total bytes:\n%s\n%s (byte %d)" % (
            processed, repr(memory+future), '-' * (len(repr(memory))-1) + '^', pos )
        log.error( "EtherNet/IP CIP error %s\n", where )

        raise
