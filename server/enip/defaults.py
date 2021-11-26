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
                                    'config_name', 'config_files', 'config_open', 'config_open_deduced', 'ConfigNotFoundError',
                                    'forward_open_default' ]

import os
import glob
import fnmatch

from ...dotdict		import dotdict
from ...automata	import type_str_base

latency				=  0.1		# network I/O polling (should allow several round-trips)
timeout				= 20.0		# Await completion of all I/O, thread activity (on many threads)
address				= ('', 44818)	# The default cpppo.enip.address

# Default assumes target (eg. CPU) in backplane, slot 0
route_path_default		= '1/0'		# default controller address: backplane, slot 0
send_path_default		= '@6/1'	# Connection Manager

# Round-trip request timeout; each node in the route_path subtracts 2x is est. rx-to-processing time (or 512ms)
priority_time_tick		= 5		#  2**5 == 32ms/tick See: Vol 3.15, 3-5.5.1.4 Connection Timing
timeout_ticks			= 157		#  157 * 32 == 5.024s

# Define the default paths used for configuration files, etc.
config_name			= 'cpppo.cfg'	# Default Cpppo application configuration file

def config_paths( filename, extra=None ):
    """Yield the Cpppo configuration search paths in *reverse* order of precedence (furthest or most
    general, to nearest or most specific).

    This is the order that is required by configparser; settings configured in "later" files
    override those in "earlier" ones.

    For other purposes (eg. loading complete files), the order is likely reversed!  The caller must
    do this manually.

    """
    yield os.path.join( os.path.dirname( __file__ ), '..', '..', filename )	# cpppo installation root dir
    yield os.path.join( os.getenv( 'APPDATA', os.sep + 'etc' ), filename )	# global app data dir, eg. /etc/
    yield os.path.join( os.path.expanduser( '~' ), '.cpppo', filename )		# user dir, ~username/.cpppo/name
    yield os.path.join( os.path.expanduser( '~' ), '.' + filename )		# user dir, ~username/.name
    for e in extra or []:							# any extra dirs...
        yield os.path.join( e, filename )
    yield filename								# current dir (most specific)
    
# Default Cpppo configuration files path, In 'configparser' expected order (most general to most specific)
config_files			= list( config_paths( config_name ))

try:
    ConfigNotFoundError		= FileNotFoundError
except NameError:
    ConfigNotFoundError		= IOError # Python2 compatibility


def config_open( name, mode=None, extra=None, skip=None, reverse=True, **kwds ):
    """Find and open all glob-matched file name(s) found on the standard or provided configuration file
    paths (plus any extra), in most general to most specific order.  Yield the open file(s), or
    raise a ConfigNotFoundError (a FileNotFoundError or IOError in Python3/2 if no matching file(s)
    at all were found, to be somewhat consistent with a raw open() call).
    
    We traverse these in reverse order by default: nearest and most specific, to furthest and most
    general, and any matching file(s) in ascending sorted order; specify reverse=False to obtain the
    files in the most general/distant configuration first.

    By default, we assume the matching target file(s) are UTF-8/ASCII text files, and default to
    open in 'r' mode.

    A 'skip' glob pattern or predicate function taking a single name and returning True/False may be
    supplied.

    """
    if isinstance( skip, type_str_base ):
        filtered		= lambda names: (n for n in names if not fnmatch.fnmatch( n, skip ))
    elif hasattr( skip, '__call__' ):
        filtered		= lambda names: (n for n in names if not skip( n ))
    elif skip is None:
        filtered		= lambda names: names
    else:
        raise AssertionError( "Invalid skip={!r} provided".format( skip ))

    search			= list( config_paths( name, extra=extra ))
    if reverse:
        search			= reversed( search )
    for fn in search:
        for gn in sorted( filtered( glob.glob( fn ))):
            try:
                yield open( gn, mode=mode or 'r', **kwds )
            except:
                # The file couldn't be opened (eg. permissions)
                pass


def deduce_name( basename=None, extension=None, filename=None, package=None ):
    assert basename or ( filename or package ), \
        "Cannot deduce basename without either filename (__file__) or package (__package__)"
    if basename is None:
        if filename:
            basename		= os.path.basename( filename ) # eg. '/a/b/c/d.py' --> 'd.py'
            if '.' in basename:
                basename	= basename[:basename.rfind( '.' )] # up to last '.'
        else:
            basename		= package
            if '.' in basename:
                basename	= basename[:basename.find( '.' )] # up to first '.'
    name			= basename
    if extension and '.' not in name:
        if extension[0] != '.':
            name	       += '.'
        name		       += extension
    return name


def config_open_deduced( basename=None, mode=None, extension=None, filename=None, package=None, **kwds ):
    """Find any glob-matched configuration file(s), optionally deducing the basename from the provided
    __file__ filename or __package__ package name, returning the open file or raising a ConfigNotFoundError
    (or FileNotFoundError, or IOError in Python2).

    """
    for f in config_open(
            name=deduce_name(
                basename=basename, extension=extension, filename=filename, package=package ),
            mode=mode or 'r', **kwds ):
        yield f


# Forward Open has Connection Path and Path (in addition to the Send RR Data's Route Path and Send Path)
forward_open_default		= dotdict({
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
       #'NCP':			   0x43FE,	# (!exclusive, p2p, lo-prio, variable size 510)
        'size':			      510,	# Connection Size
        'type':				2,      # Null/Multicast/Point-to-Point/Reserved
        'priority':			0,      # Low Prio./High Prio./Scheduled/Urgent
        'variable':			1,      # Fixed/Variable
        'redundant':			0,	# Exclusive/Redundant
    },
    'O_T': {
        'RPI':		       0x001E8480,	# 2000ms
       #'NCP':			   0x43FE,	# (!exclusive, p2p, lo-prio, variable size 510)
        'size':			      510,	# Connection Size
        'type':				2,      # Null/Multicast/Point-to-Point/Reserved
        'priority':			0,      # Low Prio./High Prio./Scheduled/Urgent
        'variable':			1,      # Fixed/Variable
        'redundant':			0,	# Exclusive/Redundant
    }
})

class Connection( object ):
    """Creates a valid encoded Large/Small Fwd.Open Connection NCP, etc. value, from either a supplied
    NCP value, or from constituent parameters.

    Distinguishing a Large vs. Small Forward Open Connection is not strictly possible; the Large
    request shifts the Connection Parameters left by 16 bits, using the full lower 16 bits for the
    desired connection size.  Therefore, a Fixed, Low Prio., Null, Exclusive (all zero Connection
    Parameters) Large connection would have a zero upper 16-bit value -- and we'd mistakenly
    interpret the low 16 bits as the Connection Parameters + Size of a Small connection.  Thus, we
    must be informed if the NCP parameters+size are large or not, if the value is below 0xFFFF.
    However, since the only nondeterministic NCP value is for a Null Connection w/ a size > 512, we
    can usually safely assume that any Connection NCP value <= 0xFFFF is Small, otherwise Large.

    If you require a Large Null Connection, ensure you supply a large=True!


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
    def __init__( self, large=None, size=None, variable=None, priority=None,
                  type=None, redundant=None, NCP=None, **kwds ):
        # Save other supplied connection parameters (eg. RPI, API, connection_ID, ...)
        self.other		= dotdict( kwds )

        if large is None:
            self._large		= bool( size and size > 0x1FF ) or bool( NCP and NCP > 0xFFFF )
        else:
            self._large		= bool( large )

        assert size      is None or 0x0  <  size      <= ( 0xFFFF if self._large else 0x1FF ), \
            "Connection size {size!r} invalid".format( size=size )
        assert variable  is None or 0b00 <= variable  <= 0b01, \
            "Connection variable {variable!r} invalid".format( variable=variable )
        assert priority  is None or 0b00 <= priority  <= 0b11, \
            "Connection priority {priority!r} invalid".format( priority=priority )
        assert type      is None or 0b00 <= type      <= 0b11, \
            "Connection type {type!r} invalid".format( type=type )
        assert redundant is None or 0b00 <= redundant <= 0b01, \
            "Connection redundant {redundant!r} invalid".format( redundant=redundant )

        # If the connection is fully specified (no defaults used), we'll demand
        # any provided NCP value to match exactly!
        specificity		= { size, variable, type, redundant, priority }
        if NCP is None or None not in specificity:
            # Either no NCP provided, *or* the connection parameters are fully specified
            self._NCP		= (
                (
                      (( 1 if variable  is None else variable  ) <<  9 )
                    + (( 0 if priority  is None else priority  ) << 10 )
                    + (( 2 if type      is None else type      ) << 13 )
                    + (( 0 if redundant is None else redundant ) << 15 )
                ) << ( 16 if self._large else 0 )
            ) + ( size or ( 4000 if self._large else 510 ))
        else:
            # No NCP provided, and/or some parameters not specified
            self._NCP		= NCP

    def __repr__( self ):
        return self.description

    @property
    def encoding( self ):
        return self._NCP

    @property
    def decoding( self ):
        """Returns connection parameters as a dict, along with any self.other kwds associated with the
        connection (eg. RPI, connection_ID, ...)

        """
        parameters		= dotdict(
            size	= self._NCP & ( 0xFFFF if self._large else 0x01FF ),
            variable	= 0b01 & self._NCP >> (  9 + ( 16 if self._large else 0 )),
            priority	= 0b11 & self._NCP >> ( 10 + ( 16 if self._large else 0 )),
            type	= 0b11 & self._NCP >> ( 13 + ( 16 if self._large else 0 )),
            redundant	= 0b01 & self._NCP >> ( 15 + ( 16 if self._large else 0 )),
            large	= self._large,
            NCP		= self._NCP,
        )
        parameters.update( self.other )
        return parameters

    # Handle some known Connection properties not related to encoding NCP
    @property
    def large( self ):
        """Get or change the Large/Small setting.  Requires re-encoding the Connection parameters

        """
        return self._large
    @large.setter
    def large( self, large ):
        if self._large != large:
            parameters		= self.decoding
            parameters.large	= large
            connection		= Connection( **parameters )
            self._NCP		= connection.encoding
            self._large		= large

    @property
    def connection_ID( self ):
        return self.other.get( 'connection_ID' )
    @connection_ID.setter
    def connection_ID( self, ID ):
        self.other.connection_ID= ID

    @property
    def RPI( self ):
        return self.other.get( 'RPI' )
    @RPI.setter
    def RPI( self, RPI ):
        self.other.RPI		= RPI

    @property
    def description( self ):
        parameters		= self.decoding
        return ( '0x%04X: ' % parameters['NCP'] ) + ', '.join((
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
        )) + ( ' + ' if self.other else '' ) + ', '.join(
            '{k} == {v!r}'.format( k=k, v=v )
            for k,v in self.other.items() )

    PRIO_LO			= 0b00
    PRIO_HI			= 0b01
    PRIO_SCH			= 0b10
    PRIO_URG			= 0b11

    TYPE_NULL			= 0b00
    TYPE_MC			= 0b01
    TYPE_P2P			= 0b10
