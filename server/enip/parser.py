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
# 
# octets	-- Scans octets to <context>_input, but does nothing with them
# octets_struct	-- Scans octets sufficient to fulfill struct 'format', and parses
# 
class octets_base( cpppo.dfa_base ):
    """Scan 'repeat' octets (default: 1), using an instance of the provided octets_state class as the
    sub-machine 'initial' state."""
    def __init__( self, name, initial=None,
                  octets_state=cpppo.state_input,
                  octets_alphabet=cpppo.type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=cpppo.type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        super( octets_base, self ).__init__( name=name, initial=octets_state(
            name="scan", terminal=True, alphabet=octets_alphabet, encoder=octets_encoder,
            typecode=octets_typecode ), **kwds )
   

class octets( octets_base, cpppo.state ):
    """Scans 'repeat' octets into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass

class octets_struct( octets_base, cpppo.state_struct ):
    """Scans octets sufficient to satisfy the specified struct 'format', and then parses it according to
    the supplied struct 'format'."""
    def __init__( self, name, format=None, **kwds ):
        assert isinstance( format, str ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, repeat=struct.calcsize( format ),
                                               format=format, **kwds )


class uint( octets_struct ):
    """An EtherNet/IP UINT; 16-bit little-endian unsigned integer"""
    def __init__( self, name, **kwds ):
        super( uint, self ).__init__( name=name, format='<H', **kwds )

class udint( octets_struct ):
    """An EtherNet/IP UDINT; 32-bit little-endian unsigned integer"""
    def __init__( self, name, **kwds ):
        super( udint, self ).__init__( name=name, format='<I', **kwds )
        
class enip_header( cpppo.dfa ):
    """Scans an EtherNet/IP encapsulation header:
    
        data.<context>.command		uint
        data.<context>.length		uint
        data.<context>.session_handle	udint
        data.<context>.status		udint
        data.<context>.sender_context	octets[8]
        data.<context>.options		udint

    Does *not* scan the command-specific data which (normally) follows the header."""
    def __init__( self, name, **kwds ):
        cmnd			= uint(		"command",		context="command" )
        cmnd[None] = leng	= uint(		"length",		context="length" )
        leng[None] = sess	= udint(	"session_handle",	context="session_handle" )
        sess[None] = stts	= udint(	"status",		context="status" )
        stts[None] = ctxt	= octets(	"sender_context",	context="sender_context", repeat=8 )
        ctxt[None] = opts	= udint( 	"options",		context="options" )
        opts[None]		= cpppo.state(	"done", terminal=True )
        super( enip_header, self ).__init__( name=name, initial=cmnd, **kwds )

class enip_machine( cpppo.dfa ):
    """Parses a complete EtherNet/IP message, including command-specific payload into
    '.encapsulated_data.input'."""
    def __init__( self, name, **kwds ):
        ehdr			= enip_header(	"header",		context="header" )
        ehdr[None] = encp	= octets(	"encapsulated_data",	context="encapsulated_data", repeat="..header.length" )
        encp[None]		= cpppo.state(	"done", terminal=True )
        super( enip_machine, self ).__init__( name=name, initial=ehdr, **kwds )
