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

class octets_base( cpppo.dfa_base ):
    """Parses 'repeat' octets (default: 1).  """
    def __init__( self, name, initial=None,
                  octets_state=cpppo.state_input,
                  octets_alphabet=cpppo.type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=cpppo.type_bytes_array_symbol,
                  context=None, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        super( octets_base, self ).__init__( name=name, context=context, initial=octets_state(
            name="scan", terminal=True, alphabet=octets_alphabet, encoder=octets_encoder,
            typecode=octets_typecode ), **kwds )
   

class octets( octets_base, cpppo.state ):
    pass

class octets_struct( octets_base, cpppo.state_struct ):
    """Scans octets sufficient to satisfy the spcified struct 'format', and then parses it."""
    def __init__( self, name, format=None, **kwds ):
        assert isinstance( format, str ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, repeat=struct.calcsize( format ),
                                               format=format, **kwds )

    
'''
class octet( cpppo.dfa ):
    """Parses the specified count of octets into <context>_input.  Default to parse a raw bytes source alphabet."""
    def __init__( self, name, count=None, context=None, alphabet=cpppo.type_bytes_iter,
                  **kwds):
        assert count is not None, "Must specify a count of octets to parse"
        read		= cpppo.dfa(   "read",
                                       initial=state_input( "byte", context=context, terminal=True ),
                                       repeat=count )
        final		= cpppo.state( "done", terminal=True )
        read[None]	= final
        super( octets, self ).__init__( name, initial=read, **kwds )


class struct( cpppo.dfa ):
    """From the size of the specified struct format, parses and then converts the
    required number of octets.

    """
    def __init__( self, name, format, **kwds ):
        count		= struct
        convert		= cpppo.state_struct( "convert", format )



'''
