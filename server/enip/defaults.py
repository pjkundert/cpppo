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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


"""
enip.defaults -- System-wide default (global) values

"""
__all__				= [ 'latency', 'timeout', 'address',
                                    'route_path_default', 'send_path_default',
                                    'priority_time_tick', 'timeout_ticks',
                                    'config_name', 'config_files',
                                    'forward_open_default' ]

import os

import cpppo

latency				=  0.1		# network I/O polling (should allow several round-trips)
timeout				= 20.0		# Await completion of all I/O, thread activity (on many threads)
address				= ('', 44818)	# The default cpppo.enip.address

# Default assumes target (eg. CPU) in backplane, slot 0, 
route_path_default		= '1/0'		# default controller address: backplane, slot 0 
send_path_default		= '@6/1'	# Connection Manager

# Round-trip request timeout; each node in the route_path subtracts 2x is est. rx-to-processing time (or 512ms)
priority_time_tick		= 5		#  2**5 == 32ms/tick See: Vol 3.15, 3-5.5.1.4 Connection Timing
timeout_ticks			= 157		#  157 * 32 == 5.024s

config_name			= 'cpppo.cfg'
config_files			= [
    os.path.join( os.path.dirname( cpppo.__file__ ), config_name ),	# cpppo install dir
    os.path.join( os.getenv( 'APPDATA', os.sep + 'etc' ), config_name ),# global app data
    os.path.join( os.path.expanduser( '~' ), '.' + config_name ),	# user home dir
    config_name,							# current dir
]

# Forward Open has Connection Path and Path (in addition to the Send RR Data's Route Path and Send Path)
forward_open_default		= cpppo.dotdict({
    'path':			   '@6/1',	# Connection Manager
    'connection_path':	       '1/0/@2/1',	# Backplane slot 0 (CPU), Message Router
    'transport_class_triggers':	     0xa3,	# dir-server, trig-app-object, class-3
    'priority_time_tick': priority_time_tick,
    'timeout_ticks':	    timeout_ticks,
    'connection_timeout_multiplier':    0,
    'O_serial':		       0x00000001,
    'O_vendor':			   0x1234,
    'T_O': {
        'RPI':		       0x001E8480,	# 2000ms
        'NCP':			   0x43F4,	# (!exclusive, p2p, lo-prio, variable size 500)
        'size':			      500,	# Connection Size
        'type':				2,      # Null/Multicast/Point-to-Point/Reserved
        'priority':			0,      # Low Prio./High Prio./Scheduled/Urgent
        'variable':			1,      # Fixed/Variable
        'redundant':			0,	# Exclusive/Redundant
    },
    'O_T': {
        'RPI':		       0x001E8480,	# 2000ms
        'NCP':			   0x43F4,	# (!exclusive, p2p, lo-prio, variable size 500)
        'size':			      500,	# Connection Size
        'type':				2,      # Null/Multicast/Point-to-Point/Reserved
        'priority':			0,      # Low Prio./High Prio./Scheduled/Urgent
        'variable':			1,      # Fixed/Variable
        'redundant':			0,	# Exclusive/Redundant
    }
})

class Connection( object ):
    """Creates a valid encoded Large/Small Fwd.Open Connection NCP, etc. value, from either a supplied
    NCP value, or from constituent parameters.

    Distinguishing a Large vs. Small Forward Open Connection is not possible; the Large request
    shifts the Connection Parameters left by 16 bits, using the full lower 16 bits for the desired
    connection size.  Therefore, a Fixed, Low Prio., Null, Exclusive (all zero Connection
    Parameters) Large connection would have a zero upper 16-bit value -- and we'd mistakenly
    interpret the low 16 bits as the Connection Parameters + Size of a Small connection.  Thus, we
    must be informed if the NCP parameters+size are large or not.

    From Vol 1_3 section 3-5.5.1.1, Network Connection Parameters

    The Network Connection Parameters in the Forward_Open shall be provided as a single
    16-bit word that contains the fields in the following figure:

    Table 3-5.9 Network Connection Parameters for Forward_Open
    3-5.5.1.1
    | 15 | 14 | 13 | 12 | 11 | 10 |  9 | 8-0 |
      ^^   ^^^^^^^   ^^   ^^^^^^^   ^^   ^^^
      |    |         |    |         |    Connection Size
      |    |         |    |         Fixed/Variable
      |    |         |    Priority
      |    |         Reserved
      |    Connection Type
      Redundant Owner

    The Network Connection Parameters in the Large_Forward_Open shall be provided as a
    single 32-bit word that contains the fields in the following figure:

    | 31 | 30 | 29 | 28 | 27 | 26 | 25 | 24-16 | 15-0 |
      ^^   ^^^^^^^   ^^   ^^^^^^^   ^^   ^^^^^   ^^^^
      |    |         |    |         |    |       Connection Size
      |    |         |    |         |    Reserved
      |    |         |    |         Fixed/Variable
      |    |         |    Priority
      |    |         Reserved
      |    Connection Type
      Redundant Owner

    So, Large is just shifted left by 16 bits, and 9 bits are ignored.

    Store extra key/value pairs associated with the connection in the self.other dict.

    """
    def __init__( self, large=False, size=None, variable=None, priority=None,
                  type=None, redundant=None, NCP=None, **kwds ):
        # Save other supplied connection parameters (eg. RPI, API, connection_ID, ...)
        self.other		= cpppo.dotdict( kwds )

        assert size or large is not None # Either large / NCP or a non-zero size are required; can't deduce
        assert NCP       is None or { size, variable, type, redundant, priority } == { None }
        assert size      is None or 0x0  <  size      <= 0xFFFF
        assert variable  is None or 0b00 <= variable  <= 0b01
        assert priority  is None or 0b00 <= priority  <= 0b11
        assert type      is None or 0b00 <= type      <= 0b11
        assert redundant is None or 0b00 <= redundant <= 0b01
        self.large		= size >= 512 if large is None else bool( large )

        # If the connection is fully specified (no defaults used), we'll demand
        # any provided NCP value to match exactly!
        specificity		= { size, variable, type, redundant, priority }
        if NCP is None or None not in specificity:
            # Either no NCP provided, *or* the connection parameters are fully specified
            self._NCP		= (
                (
                      ( variable  or 1 ) <<  9
                    + ( priority  or 0 ) << 10
                    + ( type      or 2 ) << 13
                    + ( redundant or 0 ) << 15
                )
                << ( 16 if self.large else 0 )
                + ( size or ( 4000 if self.large else 500 ))
            )
        else:
            # No NCP provided, and/or some parameters not specified
            self._NCP		= NCP

    @property
    def encoding( self ):
        return self._NCP

    @property
    def decoding( self ):
        """Returns connection parameters as a dict, along with any self.other kwds associated with the
        connection (eg. RPI, connection_ID, ...)

        """
        parameters		= cpppo.dotdict(
            size	= self._NCP & ( 0xFFFF if self.large else 0x01FF ),
            variable	= 0b01 & self._NCP >> (  9 + ( 16 if self.large else 0 )),
            priority	= 0b11 & self._NCP >> ( 10 + ( 16 if self.large else 0 )),
            type	= 0b11 & self._NCP >> ( 13 + ( 16 if self.large else 0 )),
            redundant	= 0b01 & self._NCP >> ( 15 + ( 16 if self.large else 0 )),
            large	= self.large,
            NCP		= self._NCP,
        )
        parameters.update( self.other )
        return parameters

    @property
    def description( self ):
        parameters		= self.decoding
        return ', '.join((
            ('Small', 'Large')[
                parameters['large']],
            ('%d-Byte' % parameters['size']),
            ('Fixed','Variable')[
                parameters['variable']],
            ('Low Prio.','High Prio.','Scheduled','Urgent')[
                parameters['priority']],
            ('Null','Multicast','Point-to-Point','Reserved')[
                parameters['type']],
            ('Exclusive','Redundant')[
                parameters['redundant']]
        ))

    PRIO_LO			= 0b00
    PRIO_HI			= 0b01
    PRIO_SCH			= 0b10
    PRIO_URG			= 0b11

    TYPE_NULL			= 0b00
    TYPE_MC			= 0b01
    TYPE_P2P			= 0b10
