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
enip/parser.py	-- The EtherNet/IP CIP protocol parsers

"""

import array
import codecs
import errno
import json
import logging
import os
import struct
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

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "enip.srv" )

# 
# octets_base	-- A dfa_base mixin that defaults to scan octets from bytes data
# octets	-- Scans octets to <context>.input arrray, but does nothing with them
# octets_encode	--   and converts array of octets back to a bytes string
# octets_struct	-- Scans octets sufficient to fulfill struct 'format', and parses
# 
class octets_base( cpppo.dfa_base ):
    """Scan 'repeat' octets (default: 1), using an instance of the provided octets_state class as the
    sub-machine 'initial' state.  The sub-machine is not greedy, and will terminate after accepting
    and processing exactly one symbol.  Only after all 'repeat' loops will self.terminal be True."""
    def __init__( self, name, initial=None,
                  octets_state=cpppo.state_input,
                  octets_alphabet=cpppo.type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=cpppo.type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        super( octets_base, self ).__init__( name=name, initial=octets_state(
            name="byte", terminal=True, alphabet=octets_alphabet, encoder=octets_encoder,
            typecode=octets_typecode ), **kwds )
   

class octets( octets_base, cpppo.state ):
    """Scans 'repeat' octets into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass


def octets_encode( value ):
    return value.tostring() if sys.version_info.major < 3 else value.tobytes()


class octets_struct( octets_base, cpppo.state_struct ):
    """Scans octets sufficient to satisfy the specified struct 'format', and then parses it according to
    the supplied struct 'format'."""
    def __init__( self, name, format=None, **kwds ):
        assert isinstance( format, str ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, repeat=struct.calcsize( format ),
                                               format=format, **kwds )

# 
# uint		-- Parse a 16-bit EtherNet/IP unsigned int 
# uint_encode	--   and convert a value back to a 16-bit EtherNet/IP unsigned int
# udint		-- Parse a 32-bit EtherNet/IP unsigned int 
# udint_encode	--   and convert a value back to a 32-bit EtherNet/IP unsigned int
# 
class uint( octets_struct ):
    """An EtherNet/IP UINT; 16-bit little-endian unsigned integer"""
    def __init__( self, name, **kwds ):
        super( uint, self ).__init__( name=name, format='<H', **kwds )

def uint_encode( value ):
    return struct.pack( '<H', value )

class udint( octets_struct ):
    """An EtherNet/IP UDINT; 32-bit little-endian unsigned integer"""
    def __init__( self, name, **kwds ):
        super( udint, self ).__init__( name=name, format='<I', **kwds )

def udint_encode( value ):
    return struct.pack( '<I', value )
        

# 
# enip_header	-- Parse an EtherNet/IP header only 
# enip_machine	-- Parses an EtherNet/IP header and encapsulated data payload
# enip_encode	--   and convert parsed EtherNet/IP data back into a message
# 
class enip_header( cpppo.dfa ):
    """Scans either a complete EtherNet/IP encapsulation header, or nothing (EOF), into the context
    (default 'header'):
    
        data.<context>.command		uint         2
        data.<context>.length		uint         2
        data.<context>.session_handle	udint        4
        data.<context>.status		udint        4
        data.<context>.sender_context	octets[8]    8
        data.<context>.options		udint        4
                                                    --
                                                    24

    Does *not* scan the command-specific data which (normally) follows the header.

    Each protocol element transitions to the next required element on any (non-None) symbol; we
    don't use None (no-input) transition, because we don't want to skip thru the state machine when
    no input is available."""
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'header' )
        name 			= name or kwds.get( 'context' )
        init			= cpppo.state(  "empty",  terminal=True )
        init[True] = cmnd	= uint(		"command",	context="command" )
        cmnd[True] = leng	= uint(		"length",	context="length" )
        leng[True] = sess	= udint(	"sess_hdl",	context="session_handle" )
        sess[True] = stts	= udint(	"status",	context="status" )
        stts[True] = ctxt	= octets(	"sndr_ctx",	context="sender_context",
                                    repeat=8 )
        ctxt[True] = opts	= udint( 	"options",	context="options", terminal=True )

        super( enip_header, self ).__init__( name=name, initial=init, **kwds )

class enip_machine( cpppo.dfa ):
    """Parses a complete EtherNet/IP message, including command-specific payload into
    '<context>.encapsulated_data.input'.  Context defaults to 'enip' (unless explicitly set to ''),
    and name default to context."""
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'enip' )
        name 			= name or kwds.get( 'context' )
        hedr			= enip_header()
        hedr[None] = encp	= octets(	"encp_dat",	context="encapsulated_data",
                                                repeat="..header.length", terminal=True )

        super( enip_machine, self ).__init__( name=name, initial=hedr, **kwds )

def enip_encode( data ):
    """Produce an encoded EtherNet/IP message from the supplied data; assumes
    enip.encapsulated_data.input is already available."""
    result			= b''.join( [
        uint_encode(	data.enip.header.command ),
        uint_encode(len(data.enip.encapsulated_data.input )),
        udint_encode( 	data.enip.header.session_handle ),
        udint_encode( 	data.enip.header.status ),
        octets_encode(	data.enip.header.sender_context.input ),
        udint_encode(	data.enip.header.options ),
        octets_encode(	data.enip.encapsulated_data.input ),
    ])
    return result
    
def enip_format( data ):
    """Format a decoded EtherNet/IP data bundle in a human-readable form."""
    return json.dumps( data, indent=4, sort_keys=True, default=lambda obj: repr( obj ))
