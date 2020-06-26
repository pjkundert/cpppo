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
forward_open_default		= {
    'path':			   '@6/1',	# Connection Manager
    'connection_path':	       '1/0/@2/1',	# Backplane slot 0 (CPU), Message Router
    'transport_class_triggers':	     0xa3,	# dir-server, trig-app-object, class-3
    'priority_time_tick': priority_time_tick,
    'timeout_ticks':	    timeout_ticks,
    'connection_timeout_multiplier':    0,
    'O_serial':		       0x00000001,
    'O_vendor':			   0x1234,
    'T_O_RPI':		       0x001E8480,	# 2000ms
    'T_O_NCP':			   0x43F4,	# (!exclusive, p2p, lo-prio, variable size 500)
    'O_T_RPI':		       0x001E8480,	# 2000ms
    'O_T_NCP':			   0x43F4,	# (!exclusive, p2p, lo-prio, variable size 500)
}
